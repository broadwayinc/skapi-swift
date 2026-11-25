import Foundation

/// Account methods, ported from skapi-py (_user.py) and skapi-js (src/methods/user.ts): sign-up,
/// sign-in (with authenticator app MFA), sessions, profile, password and e-mail verification, and
/// user search.
extension Skapi {
    static let anonymousKeepAlive: TimeInterval = 600
    static let anonymousRecheck: TimeInterval = 60  // a return within a minute of the last confirmation needs no check
    static let customAttributes: Set<String> = ["email_public", "address_public", "gender_public", "birthdate_public",
                                                "phone_number_public", "misc", "service", "owner"]

    // ---- helpers ----------------------------------------------------------------------------------

    func cognitoName(_ name: String) -> String {
        name.contains(service + "-") ? name : "\(service)-\(MD5JS.hash(name))"
    }

    func refuseAnonymous(_ what: String) throws {
        if isAnonymous { throw SkapiError("Anonymous accounts cannot \(what).", code: "INVALID_REQUEST") }
    }

    func requireSession() async throws {
        try await ensureConnection()
        if !(await signedIn()) { throw SkapiError("User login is required.", code: "INVALID_REQUEST") }
    }

    var profile: JSON { userObj.map { .object($0) } ?? .null }

    // ---- sign-in ------------------------------------------------------------------------------

    func authenticate(_ name: String, _ password: String, raw: Bool = false, isOpenID: Bool = false) async throws -> JSON {
        requestSignupConfirmation = nil
        disabledAccount = nil
        pendingMFA = nil
        let pool = try await userPool()
        let username = raw ? name : cognitoName(name)
        do {
            let (srpUsername, session) = try await pool.authenticate(username: username, password: password)
            try adoptSession(srpUsername, session)
            disabledAccount = nil
            await encAfterLogin(password)
            return profile
        } catch let ch as Challenge {
            return try await handleChallenge(ch, username: username, password: password)
        } catch let err as CognitoError {
            let message = err.message ?? ""
            switch err.code {
            case "NotAuthorizedException":
                if message.contains("User is disabled.") {
                    disabledAccount = username
                    throw SkapiError("This account is disabled.", code: "USER_IS_DISABLED", cause: err)
                }
                if isOpenID { throw SkapiError("The account already exists.", code: "ACCOUNT_EXISTS", cause: err) }
                throw SkapiError("Incorrect username or password.", code: "INCORRECT_USERNAME_OR_PASSWORD", cause: err)
            case "UserNotFoundException":
                throw SkapiError("Incorrect username or password.", code: "INCORRECT_USERNAME_OR_PASSWORD", cause: err)
            case "UserNotConfirmedException":
                requestSignupConfirmation = username
                throw SkapiError("User's signup confirmation is required.", code: "SIGNUP_CONFIRMATION_NEEDED", cause: err)
            case "TooManyRequestsException", "LimitExceededException":
                throw SkapiError("Too many attempts. Please try again later.", code: "REQUEST_EXCEED", cause: err)
            case "NetworkError":
                throw SkapiError("Network error", code: "NETWORK_ERROR", cause: err)
            default:
                let parsed = parsedCognitoError(err)
                if parsed.code == "SIGNUP_CONFIRMATION_NEEDED" { requestSignupConfirmation = username }
                throw parsed
            }
        }
    }

    private func handleChallenge(_ ch: Challenge, username: String, password: String) async throws -> JSON {
        let pool = try await userPool()
        let srpUsername = ch.parameters["USER_ID_FOR_SRP"]?.string ?? username
        switch ch.name {
        case "NEW_PASSWORD_REQUIRED":
            disabledAccount = nil
            requestSignupConfirmation = username
            let attrs = (ch.parameters["userAttributes"]?.string).flatMap { try? JSON.parse($0) } ?? [:]
            if let t = attrs["custom:signup_ticket"]?.string, ["PASS", "MEMBER", "OIDPASS"].contains(t) {
                // an account an admin created, an invitation, or an OpenID account: confirmed by setting the same password
                let session: SkapiSession
                do {
                    session = try await pool.completeNewPassword(username: srpUsername, newPassword: password, challengeSession: ch.session)
                } catch let next as Challenge {
                    return try await handleChallenge(next, username: username, password: password)
                } catch let err as CognitoError {
                    throw SkapiError(err.message ?? "Failed to authenticate user.", code: err.code, cause: err)
                }
                try adoptSession(srpUsername, session)
                await encAfterLogin(password)
                return profile
            }
            throw SkapiError("User's signup confirmation is required.", code: "SIGNUP_CONFIRMATION_NEEDED")
        case "SOFTWARE_TOKEN_MFA":
            // the password stays in memory only until verifyMFA, to open the encryption keyring
            pendingMFA = (srpUsername, ch.session, password)
            throw SkapiError("A code from the authenticator app is required to sign in. Call verifyMFA() with the code.", code: "MFA_REQUIRED")
        case "SELECT_MFA_TYPE":
            let next = try await pool.selectMFAType(username: srpUsername, answerName: "SOFTWARE_TOKEN_MFA", challengeSession: ch.session)
            return try await handleChallenge(next, username: username, password: password)
        case "SMS_MFA":
            throw SkapiError("Sign-in codes by SMS are not supported.", code: "INVALID_REQUEST")
        case "MFA_SETUP":
            throw SkapiError("The account must set up an authenticator app before signing in.", code: "INVALID_REQUEST")
        default:
            throw SkapiError("Unsupported sign-in step: \(ch.name).", code: "INVALID_REQUEST")
        }
    }

    /// Signs in with the e-mail (or username) and password. Returns the user's profile.
    /// Throws code `MFA_REQUIRED` when the account has two-step login on: call `verifyMFA(code:)`.
    @discardableResult
    public func login(email: String? = nil, username: String? = nil, password: String) async throws -> JSON {
        _ = try await userPool()
        var email = email, username = username
        var normalized: String?
        if let e = email, !e.isEmpty {
            do { normalized = try Check.email(.string(e)) }
            catch { username = e; email = nil }
        }
        let typed = (username?.isEmpty == false ? username : nil) ?? (email?.isEmpty == false ? email : nil)
        guard let typedName = typed else { throw paramError("At least one of \"username\" or \"email\" is required.") }
        let first = normalized ?? typedName
        let fallback = (normalized != nil && normalized != typedName) ? typedName : nil
        do {
            return try await authenticate(first, password)
        } catch let err as SkapiError {
            let retryable = ["INCORRECT_USERNAME_OR_PASSWORD", "UserNotFoundException", "NotAuthorizedException"].contains(err.code)
            if retryable, let fb = fallback {
                do {
                    return try await authenticate(fb, password)
                } catch let second as SkapiError {
                    if ["INCORRECT_USERNAME_OR_PASSWORD", "NOT_EXISTS", "UserNotFoundException", "NotAuthorizedException"].contains(second.code) {
                        throw err
                    }
                    throw second
                }
            }
            throw err
        }
    }

    /// Finishes a login that threw MFA_REQUIRED, with the 6 digit code from the authenticator app (within 3 minutes).
    @discardableResult
    public func verifyMFA(code: String) async throws -> JSON {
        let code = try Check.mfaCode(code)
        guard let pending = pendingMFA else {
            throw SkapiError("No sign-in is waiting for an authenticator code. Call login() first.", code: "INVALID_REQUEST")
        }
        let session: SkapiSession
        do {
            session = try await userPool().sendMFACode(username: pending.username, code: code, challengeSession: pending.session)
        } catch let err as CognitoError {
            if err.code == "CodeMismatchException" { throw SkapiError("Incorrect authenticator code.", code: "INVALID_CODE", cause: err) }
            if err.code == "ExpiredCodeException" {
                throw SkapiError("This authenticator code was already used. Wait for the next code.", code: "INVALID_CODE", cause: err)
            }
            pendingMFA = nil
            if ["TooManyRequestsException", "LimitExceededException", "TooManyFailedAttemptsException"].contains(err.code) {
                throw SkapiError("Too many attempts. Please try again later.", code: "REQUEST_EXCEED", cause: err)
            }
            if err.code == "NotAuthorizedException" {
                throw SkapiError("The sign-in has expired. Call login() again.", code: "INVALID_REQUEST", cause: err)
            }
            throw parsedCognitoError(err)
        }
        pendingMFA = nil
        try adoptSession(pending.username, session)
        disabledAccount = nil
        await encAfterLogin(pending.password)
        return profile
    }

    /// Signs out. global: true also ends every session of the account on every device.
    @discardableResult
    public func logout(global: Bool = false) async throws -> String {
        await restore()
        if isAnonymous {
            _ = try? await call("anonymous-session", ["end": true], auth: true)
            clearSession()
        } else if global, sess != nil {
            do {
                _ = try await userPool().call("GlobalSignOut", accessToken: accessToken())
            } catch let err as CognitoError {
                throw parsedCognitoError(err)
            }
            clearSession()
        } else {
            clearSession()
        }
        return "SUCCESS: The user has been logged out."
    }

    /// The signed-in user's profile, or nil. refreshToken: true asks the server for fresh tokens first.
    public func getProfile(refreshToken: Bool = false) async -> JSON? {
        if !refreshToken { return await user }
        await restore()
        do {
            if let s = sess, restoreRefreshedToken == s.idToken.jwtToken {
                // the stored tokens had expired and were just refreshed: one refresh, not two
                restoreRefreshedToken = nil
            } else {
                try await refreshSession(newClaims: true)
            }
            return userObj.map { .object($0) }
        } catch {
            return nil
        }
    }

    /// Adopts the tokens of a sign-in made elsewhere (for example skapi-js on a web page, or your
    /// own server). All three tokens are needed to make signed-in calls.
    @discardableResult
    public func loginWithToken(idToken: String, accessToken: String, refreshToken: String) async throws -> JSON {
        for (name, value) in [("idToken", idToken), ("accessToken", accessToken), ("refreshToken", refreshToken)] where value.isEmpty {
            throw paramError("\"\(name)\" is required.")
        }
        let payload = JwtToken(idToken).payload
        if payload["custom:service"]?.string != service {
            throw SkapiError("Token does not belong to this service.", code: "INVALID_REQUEST")
        }
        if (payload["exp"]?.number ?? 0) < Date().timeIntervalSince1970 {
            throw SkapiError("Token has expired.", code: "INVALID_REQUEST")
        }
        await restore()
        let session = SkapiSession(idToken: idToken, accessToken: accessToken, refreshToken: refreshToken)
        let username = payload["cognito:username"]?.string ?? ""
        try adoptSession(username, session)
        try await userPool().cacheTokens(username, session)
        return profile
    }

    // ---- sign-up --------------------------------------------------------------------------------

    /// Creates an account. params: email and password (required), and any profile fields.
    /// option: signup_confirmation (true or a redirect URL), email_subscription, login (sign in right
    /// after), template. Returns a "SUCCESS: ..." string, or the profile with `"login": true`.
    @discardableResult
    public func signup(_ params: JSON, option: JSON? = nil) async throws -> JSON {
        _ = try await userPool()
        let params = params.object ?? JSONObject()
        let option = option?.object ?? JSONObject()
        if !params.contains("email") { throw paramError("Key \"email\" is required.") }
        if !params.contains("password") { throw paramError("Key \"password\" is required.") }
        var p = JSONObject()
        let checks: [(String, (JSON) throws -> JSON)] = [
            ("username", Check.string("username")), ("password", { .string(try Check.password($0)) }), ("email", { .string(try Check.email($0)) }),
            ("name", Check.string("name")), ("address", Check.address), ("gender", Check.string("gender")), ("birthdate", Check.birthdate),
            ("phone_number", Check.phone), ("misc", Check.string("misc")), ("picture", Check.url), ("profile", Check.url),
            ("family_name", Check.string("family_name")), ("given_name", Check.string("given_name")),
            ("middle_name", Check.string("middle_name")), ("nickname", Check.string("nickname")), ("website", Check.url),
        ]
        for (k, f) in checks { if let v = params[k] { p[k] = try f(v) } }
        for k in ["email_public", "address_public", "gender_public", "birthdate_public", "phone_number_public"] {
            p[k] = params[k]?.isBool == true ? params[k] : false
        }

        try await logout()

        var sc = option["signup_confirmation"] ?? false
        if sc.isString { sc = try Check.url(sc) }
        else if !sc.isBool { throw paramError("\"option.signup_confirmation\" should be type: <string | boolean>.") }
        if sc.truthy && !p["email"].truthy { throw paramError("\"email\" is required for signup confirmation.") }
        let es = option["email_subscription"] ?? false
        let esOK: Bool = {
            if es.isBool || es.isString { return true }
            if let n = es.number { return n == 0 || n == 1 }
            return false
        }()
        if !esOK { throw paramError("\"option.email_subscription\" takes 0 (public), 1 (authorized), true, false or the name of a newsletter group.") }
        if es != .bool(false) && !sc.truthy { throw paramError("\"option.signup_confirmation\" is required for email subscription.") }
        let loginAfter = option["login"] ?? false
        guard let loginAfterBool = loginAfter.bool else { throw paramError("\"option.login\" should be type: boolean.") }
        if loginAfterBool && sc.truthy { throw paramError("\"login\" is not allowed when \"option.signup_confirmation\" is true.") }
        let templateValue = option["template"].flatMap { $0.truthy ? $0 : nil } ?? .object(JSONObject())
        guard let template = templateValue.object else { throw paramError("\"option.template\" should be type: <object>.") }
        for key in ["signup_confirmation", "welcome"] where template.contains(key) {
            if !(template[key]?.string.map { !$0.isEmpty } ?? false) {
                throw paramError("\"option.template.\(key)\" should be a non-empty <string> (template message_id).")
            }
        }
        if template["signup_confirmation"].truthy && !sc.truthy {
            throw paramError("\"option.signup_confirmation\" is required when \"option.template.signup_confirmation\" is set.")
        }
        if p["email_public"].truthy && !sc.truthy {
            throw paramError("\"option.signup_confirmation\" should be true if \"email_public\" is set to true.")
        }

        let base = (p["username"].truthy ? p["username"]?.string : nil) ?? p["email"]?.string ?? ""
        let cognitoUsername = cognitoName(base)
        let keyReply = try await call("signupkey", [
            "username": .string(cognitoUsername),
            "signup_confirmation": sc.isBool ? .string(sc.bool! ? "true" : "false") : sc,
            "email_subscription": es,
            "template_confirmation": template["signup_confirmation"].truthy ? template["signup_confirmation"]! : "",
            "template_welcome": template["welcome"].truthy ? template["welcome"]! : "",
        ])
        let parts = keyReply.pyString.components(separatedBy: ":")
        let signupKey = parts[0], signupTicket = parts.dropFirst().joined(separator: ":")
        let ticketParts = signupTicket.components(separatedBy: "#")
        var attributes: [JSON] = [
            ["Name": "custom:signup", "Value": .string(signupKey)],
            ["Name": "locale", "Value": .string(ticketParts.count > 1 ? ticketParts[1] : "")],
            ["Name": "custom:signup_ticket", "Value": .string(signupTicket)],
        ]
        var values = p
        values["service"] = .string(service)
        values["owner"] = .string(owner)
        for k in ["email", "name", "address", "gender", "birthdate", "phone_number", "email_public", "address_public", "gender_public",
                  "birthdate_public", "phone_number_public", "misc", "picture", "profile", "family_name", "given_name", "middle_name",
                  "nickname", "website", "service", "owner"] {
            var v = values[k] ?? .null
            if v == .string("") { continue }
            if k.hasSuffix("_public") { v = .string(v.truthy ? "1" : "0") }
            attributes.append(["Name": .string(Skapi.customAttributes.contains(k) ? "custom:\(k)" : k),
                               "Value": .string(v.isNull ? "" : v.pyString)])
        }
        do {
            _ = try await userPool().signUp(username: cognitoUsername, password: p["password"]?.string ?? "", attributes: attributes)
        } catch let err as CognitoError {
            let parsed = parsedCognitoError(err)
            switch err.code {
            case "UsernameExistsException": throw SkapiError("The account already exists.", code: "EXISTS", cause: err)
            case "InvalidPasswordException":
                throw SkapiError("Invalid password. Password must be at least 6 characters.", code: "INVALID_PARAMETER", cause: err)
            case "InvalidParameterException": throw SkapiError(parsed.message, code: "INVALID_PARAMETER", cause: err)
            case "TooManyRequestsException", "LimitExceededException":
                throw SkapiError("Too many attempts. Please try again later.", code: "REQUEST_EXCEED", cause: err)
            case "CodeDeliveryFailureException": throw SkapiError("Failed to deliver verification code.", code: "CODE_DELIVERY_FAILURE", cause: err)
            case "UserLambdaValidationException":
                throw SkapiError(parsed.message, code: parsed.code == "EXISTS" ? "EXISTS" : "INVALID_REQUEST", cause: err)
            default: throw parsed
            }
        }
        if sc.truthy {
            requestSignupConfirmation = cognitoUsername
            return "SUCCESS: The account has been created. User's signup confirmation is required."
        }
        if loginAfterBool { return try await login(email: base, password: p["password"]?.string ?? "") }
        return "SUCCESS: The account has been created."
    }

    /// Sends the signup confirmation e-mail again, after a login answered SIGNUP_CONFIRMATION_NEEDED.
    @discardableResult
    public func resendSignupConfirmation() async throws -> JSON {
        guard let u = requestSignupConfirmation else { throw SkapiError("Least one login attempt is required.", code: "INVALID_REQUEST") }
        return try await call("confirm-signup", ["username": .string(u)])
    }

    /// Sends the recovery e-mail to a disabled account, after a login attempt answered USER_IS_DISABLED.
    /// redirect: false, true, or a URL to open after the account is recovered.
    @discardableResult
    public func recoverAccount(redirect: JSON = false) async throws -> String {
        var redirect = redirect
        if redirect.isString { redirect = try Check.url(redirect) }
        else if !redirect.isBool { throw SkapiError("Argument should be type: <boolean | string>.", code: "INVALID_REQUEST") }
        guard let d = disabledAccount else {
            throw SkapiError("Least one signin attempt of disabled account is required.", code: "INVALID_REQUEST")
        }
        _ = try await call("recover-account", ["username": .string(d), "redirect": redirect])
        return "SUCCESS: Recovery e-mail has been sent."
    }

    /// Disables the signed-in account and signs out.
    @discardableResult
    public func disableAccount() async throws -> JSON {
        try await requireSession()
        try refuseAnonymous("be disabled")
        let result = try await call("remove-account", ["disable": .string(me)], auth: true)
        try await logout()
        return result
    }

    // ---- profile and password ---------------------------------------------------------------------

    /// Changes the signed-in user's own profile fields. "" clears a field. Returns the profile.
    @discardableResult
    public func updateProfile(_ params: JSON) async throws -> JSON {
        try await requireSession()
        try refuseAnonymous("edit their profile")
        let params = params.object ?? JSONObject()
        var p = JSONObject()
        var checks: [(String, (JSON) throws -> JSON)] = [
            ("email", { .string(try Check.email($0)) }), ("address", Check.address), ("name", Check.string("name")),
            ("gender", Check.string("gender")), ("birthdate", Check.birthdate), ("phone_number", Check.phone),
            ("misc", Check.string("misc")), ("picture", Check.url), ("profile", Check.url), ("website", Check.url),
            ("family_name", Check.string("family_name")), ("given_name", Check.string("given_name")),
            ("middle_name", Check.string("middle_name")), ("nickname", Check.string("nickname")),
        ]
        for k in ["email_public", "phone_number_public", "address_public", "gender_public", "birthdate_public"] {
            checks.append((k, Check.boolean(k)))
        }
        for (k, f) in checks { if let v = params[k] { p[k] = try f(v) } }
        if p.isEmpty { return profile }
        if p["email_public"].truthy && userObj?["email_verified"]?.bool != true {
            throw SkapiError("User's e-mail should be verified to set \"email_public\" to true.", code: "INVALID_REQUEST")
        }
        let current = userObj ?? JSONObject()
        var attributes: [JSON] = []
        for (k, v) in p {
            if !v.isObject && !v.isArray, let c = current[k], c == v { continue }
            let name = Skapi.customAttributes.contains(k) ? "custom:\(k)" : k
            var value = v
            if let b = v.bool { value = .string(b ? "1" : "0") }
            attributes.append(["Name": .string(name), "Value": .string(value.isNull ? "" : value.pyString)])
        }
        if !attributes.isEmpty {
            do {
                _ = try await userPool().call("UpdateUserAttributes", accessToken: accessToken(), ["UserAttributes": .array(attributes)])
            } catch let err as CognitoError {
                throw SkapiError(err.message ?? "Failed to update user settings.", code: err.code, cause: err)
            }
            try await refreshSession(newClaims: true)
        }
        return profile
    }

    /// Changes the signed-in user's password. With encryption on, the keyring is re-wrapped first.
    @discardableResult
    public func changePassword(currentPassword: String, newPassword: String) async throws -> String {
        try await requireSession()
        try refuseAnonymous("change their password")
        if currentPassword.isEmpty { throw paramError("\"current_password\" is required to change password.") }
        if newPassword.isEmpty { throw paramError("\"new_password\" is required to change password.") }
        _ = try Check.password(.string(currentPassword), field: "current_password")
        _ = try Check.password(.string(newPassword), field: "new_password")
        // the keyring gets a wrap under the new password BEFORE the password changes (fails while locked)
        let rewrapped = try await encRewrapPassword(current: currentPassword, new: newPassword)
        do {
            _ = try await userPool().call("ChangePassword", accessToken: accessToken(),
                                          ["PreviousPassword": .string(currentPassword), "ProposedPassword": .string(newPassword)])
        } catch let err as CognitoError {
            if err.code == "InvalidParameterException" { throw SkapiError("Invalid password parameter.", code: "INVALID_PARAMETER", cause: err) }
            if err.code == "NotAuthorizedException" { throw SkapiError("Incorrect password.", code: "INVALID_REQUEST", cause: err) }
            if ["TooManyRequestsException", "LimitExceededException"].contains(err.code) {
                throw SkapiError("Too many attempts. Please try again later.", code: "REQUEST_EXCEED", cause: err)
            }
            throw parsedCognitoError(err)
        }
        if rewrapped { await encPruneWraps() }
        return "SUCCESS: Password has been changed."
    }

    /// Sends a password reset code to the account's e-mail. Then call `resetPassword`.
    /// template: ["forgot_password": "<template message_id>"].
    @discardableResult
    public func forgotPassword(email: String, template: JSON? = nil) async throws -> String {
        try await ensureConnection()
        let email = try Check.email(.string(email))
        var params: JSONObject = ["Username": .string(cognitoName(email))]
        if let t = template {
            guard let o = t.object else { throw paramError("\"template\" should be type: <object>.") }
            if o.contains("verification") {
                throw paramError("\"template.verification\" is not an option of forgotPassword(). Use \"template.forgot_password\" (template message_id).")
            }
            if let fp = o["forgot_password"] {
                guard let s = fp.string, !s.isEmpty else {
                    throw paramError("\"template.forgot_password\" should be a non-empty <string> (template message_id).")
                }
                params["ClientMetadata"] = ["template_forgot_password": .string(s)]
            }
        }
        do {
            _ = try await userPool().callPublic("ForgotPassword", params)
        } catch let err as CognitoError {
            let parsed = parsedCognitoError(err)
            let map = ["UserNotFoundException": "NOT_EXISTS", "InvalidParameterException": "INVALID_PARAMETER",
                       "NotAuthorizedException": "INVALID_REQUEST", "LimitExceededException": "REQUEST_EXCEED",
                       "TooManyRequestsException": "REQUEST_EXCEED", "CodeDeliveryFailureException": "CODE_DELIVERY_FAILURE"]
            throw SkapiError(parsed.message, code: map[err.code] ?? parsed.code, cause: err)
        }
        return "SUCCESS: Verification code has been sent."
    }

    /// Sets a new password with the code `forgotPassword` sent.
    @discardableResult
    public func resetPassword(email: String, code: String, newPassword: String) async throws -> String {
        try await ensureConnection()
        let email = try Check.email(.string(email))
        _ = try Check.password(.string(newPassword))
        do {
            _ = try await userPool().callPublic("ConfirmForgotPassword", ["Username": .string(cognitoName(email)),
                                                                         "ConfirmationCode": .string(code), "Password": .string(newPassword)])
        } catch let err as CognitoError {
            throw SkapiError(err.message ?? "Failed to reset password.", code: err.code, cause: err)
        }
        return "SUCCESS: New password has been set."
    }

    /// Without a code: sends a verification code to the user's e-mail. With a code: verifies it.
    /// template: ["verification": "<template message_id>"].
    @discardableResult
    public func verifyEmail(code: String? = nil, template: JSON? = nil) async throws -> String {
        try await ensureConnection()
        if !(await signedIn()) { throw SkapiError("The user has to be logged in.", code: "INVALID_REQUEST") }
        try refuseAnonymous("verify an e-mail")
        guard userObj?.contains("email") == true else { throw SkapiError("No e-mail to verify", code: "INVALID_REQUEST") }
        if userObj?["email_verified"]?.bool == true { return "SUCCESS: \"email\" is verified." }
        var metadata: JSON?
        if let t = template?.object, let v = t["verification"] {
            guard let s = v.string, !s.isEmpty else {
                throw paramError("\"template.verification\" should be a non-empty <string> (template message_id).")
            }
            metadata = ["template_verification": .string(s)]
        }
        do {
            if let c = code, !c.isEmpty {
                _ = try await userPool().call("VerifyUserAttribute", accessToken: accessToken(), ["AttributeName": "email", "Code": .string(c)])
                try await refreshSession(newClaims: true)
                userObj?["email_verified"] = true
                return "SUCCESS: \"email\" is verified."
            }
            var params: JSONObject = ["AttributeName": "email"]
            if let m = metadata { params["ClientMetadata"] = m }
            _ = try await userPool().call("GetUserAttributeVerificationCode", accessToken: accessToken(), params)
            return "SUCCESS: Verification code has been sent."
        } catch let err as CognitoError {
            throw SkapiError(err.message ?? "Failed to request verification code.", code: err.code, cause: err)
        }
    }

    /// Reverts the account's e-mail to the last verified one (revert: true), or tells which it is.
    public func lastVerifiedEmail(revert: Bool? = nil) async throws -> JSON {
        try await requireSession()
        try refuseAnonymous("change their e-mail")
        var body = JSONObject()
        if let r = revert { body["revert"] = .bool(r) }
        let reply = try await call("last-verified-email", .object(body), auth: true)
        if let s = reply.string, s.contains("SUCCESS") {
            try await refreshSession(newClaims: true)
            return profile
        }
        return reply
    }

    // ---- OpenID and anonymous -------------------------------------------------------------------

    /// Signs in with a token from your OpenID provider, through the OpenID logger set up as `id`.
    /// merge: true, or the profile attributes to merge into an existing account with the same e-mail.
    /// Returns ["userProfile": profile, "openid": the provider's profile].
    public func openIdLogin(token: String, id: String, merge: JSON? = nil, template: JSON? = nil) async throws -> JSON {
        try await ensureConnection()
        var body: JSONObject = ["token": .string(token), "id": .string(id)]
        if var m = merge, !m.isNull {
            if m.isString { m = .array([m]) }
            if let a = m.array {
                if !a.allSatisfy({ $0.isString }) { throw paramError("\"merge\" array items should be type: <string>.") }
            } else if !m.isBool {
                throw paramError("\"merge\" should be type: <boolean | string[]>.")
            }
            body["merge"] = m
        }
        if let t = template, !t.isNull {
            guard let o = t.object else { throw paramError("\"template\" should be type: <object>.") }
            if let w = o["welcome"] {
                guard let s = w.string, !s.isEmpty else { throw paramError("\"template.welcome\" should be a non-empty <string> (template message_id).") }
                body["template_welcome"] = .string(s)
            }
        }
        let reply = try await call("openid-logger", .object(body))
        let logger = (reply["logger"]?.pyString ?? "").components(separatedBy: "#")
        let profile = try await authenticate("\(service)-\(logger[0])", logger.count > 1 ? logger[1] : "", raw: true, isOpenID: true)
        return ["userProfile": profile, "openid": reply["openid"] ?? .null]
    }

    /// A temporary account without e-mail or password, deleted 30 minutes after this object stops
    /// keeping it alive.
    @discardableResult
    public func anonymousLogin() async throws -> JSON {
        try await ensureConnection()
        if await signedIn() {
            if isAnonymous {
                startAnonymousKeepAlive()
                return profile
            }
            throw SkapiError("A user is already logged in. Log out first.", code: "INVALID_REQUEST")
        }
        let creds = try await call("anonymous-login", .object(JSONObject()))
        let p = try await authenticate(creds["username"]?.string ?? "", creds["password"]?.string ?? "", raw: true)
        startAnonymousKeepAlive()
        return p
    }

    /// For a temporary account restored from storage: asks the server whether it still exists.
    /// Returns the profile, or nil (and signs out) when the account was already deleted. Any other
    /// user is returned as is, without a request.
    public func verifyAnonymousSession() async throws -> JSON? {
        try await ensureConnection()
        await restore()
        if !isAnonymous { return userObj.map { .object($0) } }
        do {
            _ = try await call("anonymous-session", .object(JSONObject()), auth: true)
            lastAnonymousBeat = Date()
        } catch let err as SkapiError where err.code == "NOT_EXISTS" {
            clearSession()
            return nil
        } catch {}
        return userObj.map { .object($0) }
    }

    func startAnonymousKeepAlive(beatNow: Bool = false) {
        stopAnonymousKeepAlive()
        anonymousTask = Task { [weak self] in
            var wait = beatNow ? 0 : Skapi.anonymousKeepAlive
            while !Task.isCancelled {
                if wait > 0 { try? await Task.sleep(nanoseconds: UInt64(wait * 1_000_000_000)) }
                if Task.isCancelled { return }
                guard let self = self, await self.anonymousBeat() else { return }
                wait = Skapi.anonymousKeepAlive
            }
        }
    }

    /// One keep-alive beat. false when the keep-alive should stop.
    func anonymousBeat() async -> Bool {
        guard isAnonymous else { return false }
        do {
            _ = try await call("anonymous-session", .object(JSONObject()), auth: true)
            lastAnonymousBeat = Date()
        } catch let err as SkapiError where err.code == "NOT_EXISTS" {
            anonymousTask = nil
            clearSession()
            return false
        } catch {}
        return true
    }

    func stopAnonymousKeepAlive() {
        anonymousTask?.cancel()
        anonymousTask = nil
        lastAnonymousBeat = nil
    }

    /// The app came back: an anonymous account not confirmed within the last minute is checked now,
    /// so a swept one is signed out at once (as skapi-js does when a tab becomes visible again).
    func recheckAnonymousSession() async {
        guard isAnonymous, anonymousTask != nil else { return }
        if let last = lastAnonymousBeat, Date().timeIntervalSince(last) < Skapi.anonymousRecheck { return }
        _ = await anonymousBeat()
    }

    // ---- authenticator app MFA ----------------------------------------------------------------

    private func mfaUser(_ what: String) async throws -> String {
        try await requireSession()
        try refuseAnonymous(what)
        return try await accessToken()
    }

    /// Starts two-step login setup: returns ["secret", "uri"]. Show uri as a QR code, then call `enableMFA(code:)`.
    public func setupMFA(issuer: String? = nil, accountName: String? = nil) async throws -> JSON {
        let token = try await mfaUser("set up MFA")
        let secret: String
        do {
            secret = try await userPool().call("AssociateSoftwareToken", accessToken: token)["SecretCode"]?.string ?? ""
        } catch let err as CognitoError {
            throw parsedCognitoError(err)
        }
        let conn = connection ?? JSONObject()
        func clean(_ s: String) -> String { s.replacingOccurrences(of: ":", with: " ").trimmingCharacters(in: .whitespacesAndNewlines) }
        let iss = clean((issuer?.isEmpty == false ? issuer : nil) ?? (conn["service_name"]?.string.flatMap { $0.isEmpty ? nil : $0 }) ?? service)
        let u = userObj ?? JSONObject()
        let accountRaw = (accountName?.isEmpty == false ? accountName : nil)
            ?? [u["email"], u["username"], u["user_id"]].compactMap { $0?.string }.first { !$0.isEmpty } ?? ""
        let account = clean(accountRaw)
        let label = iss.isEmpty ? encodeURIComponent(account) : "\(encodeURIComponent(iss)):\(encodeURIComponent(account))"
        let uri = "otpauth://totp/\(label)?secret=\(secret)" + (iss.isEmpty ? "" : "&issuer=\(encodeURIComponent(iss))") + "&algorithm=SHA1&digits=6&period=30"
        return ["secret": .string(secret), "uri": .string(uri)]
    }

    /// Turns two-step login on with a code from the authenticator app set up by `setupMFA`.
    @discardableResult
    public func enableMFA(code: String) async throws -> String {
        let code = try Check.mfaCode(code)
        let token = try await mfaUser("turn on MFA")
        do {
            _ = try await userPool().call("VerifySoftwareToken", accessToken: token, ["UserCode": .string(code)])
        } catch let err as CognitoError {
            if err.code == "SoftwareTokenMFANotFoundException"
                || (err.code == "InvalidParameterException" && Rx.search("software token", err.message ?? "", .caseInsensitive)) {
                throw SkapiError("Call setupMFA() first.", code: "INVALID_REQUEST", cause: err)
            }
            if ["EnableSoftwareTokenMFAException", "CodeMismatchException"].contains(err.code) {
                throw SkapiError("Incorrect authenticator code.", code: "INVALID_CODE", cause: err)
            }
            if ["TooManyRequestsException", "LimitExceededException"].contains(err.code) {
                throw SkapiError("Too many attempts. Please try again later.", code: "REQUEST_EXCEED", cause: err)
            }
            throw parsedCognitoError(err)
        }
        do {
            _ = try await userPool().call("SetUserMFAPreference", accessToken: token,
                                          ["SoftwareTokenMfaSettings": ["Enabled": true, "PreferredMfa": true]])
        } catch let err as CognitoError {
            throw parsedCognitoError(err)
        }
        return "SUCCESS: MFA has been enabled."
    }

    /// Turns two-step login off.
    @discardableResult
    public func disableMFA() async throws -> String {
        let token = try await mfaUser("turn off MFA")
        do {
            _ = try await userPool().call("SetUserMFAPreference", accessToken: token,
                                          ["SoftwareTokenMfaSettings": ["Enabled": false, "PreferredMfa": false]])
        } catch let err as CognitoError {
            throw parsedCognitoError(err)
        }
        return "SUCCESS: MFA has been disabled."
    }

    /// ["enabled": true] when two-step login is on.
    public func getMFAStatus() async throws -> JSON {
        let token = try await mfaUser("use MFA")
        let data: JSONObject
        do {
            data = try await userPool().call("GetUser", accessToken: token)
        } catch let err as CognitoError {
            throw parsedCognitoError(err)
        }
        let list = data["UserMFASettingList"]?.array ?? []
        return ["enabled": .bool(list.contains(.string("SOFTWARE_TOKEN_MFA")))]
    }

    // ---- users ----------------------------------------------------------------------------------

    /// Searches the project's users by one profile field. Signed-in users only.
    /// params: ["searchFor": field, "value": value, "condition"?: ..., "range"?: ...].
    public func getUsers(_ params: JSON? = nil, fetchOptions: FetchOptions? = nil) async throws -> JSON {
        var fo = fetchOptions?.object ?? JSONObject()
        var params = params?.object ?? JSONObject()
        if params.isEmpty {
            params = ["searchFor": "timestamp", "condition": ">", "value": 0]
            fo["ascending"] = false
        }
        let fields = ["user_id", "name", "email", "phone_number", "address", "gender", "birthdate", "locale", "subscribers",
                      "timestamp", "access_group", "approved"]
        guard let searchForValue = params["searchFor"] else { throw paramError("Key \"searchFor\" is required.") }
        guard params.contains("value") else { throw paramError("Key \"value\" is required.") }
        if searchForValue == .string("") { throw paramError("\"searchFor\" should not be an empty string.") }
        guard let searchFor = searchForValue.string, fields.contains(searchFor) else {
            throw paramError("\(jd(searchForValue)) is invalid in \"searchFor\". allowed types or values are: " +
                             fields.map { jd(.string($0)) }.joined(separator: ", ") + ".")
        }
        let conditions = [">", ">=", "=", "<", "<=", "gt", "gte", "eq", "lt", "lte"]
        var condition = params["condition"]?.string ?? "="
        if !conditions.contains(condition) { condition = "=" }

        func check(_ v: JSON, _ what: String) throws {
            switch searchFor {
            case "user_id":
                guard let s = v.string, Check.isUUID(s) else { throw paramError("User ID is invalid.") }
            case "locale":
                guard let s = v.string, s.count <= 5 else { throw paramError("Value of \"locale\" should be a country code.") }
            case "birthdate":
                _ = try Check.birthdate(v)
            case "subscribers", "timestamp", "access_group":
                if !v.isNumber { throw paramError("\(what) does not match the type of \"\(searchFor)\" index.") }
            default:
                if !v.isString { throw paramError("\(what) does not match the type of \"\(searchFor)\" index.") }
            }
        }
        let value = params["value"]!
        if let list = value.array { for v in list { try check(v, "Value") } } else { try check(value, "Value") }
        var body: JSONObject = ["searchFor": .string(searchFor), "value": value, "condition": .string(condition)]
        if let r = params["range"] {
            try check(r, "Range")
            body["range"] = r
        }
        if condition != "=" && params.contains("range") { throw paramError("Conditions does not apply on range search.") }
        if value.isArray && (condition != "=" || params["range"].truthy) {
            throw paramError("Conditions are not allowed on a list of \"\(searchFor)\" values. Search for a single value to use a condition or range.")
        }
        if value == .string("") { throw paramError("Value should not be an empty string.") }
        return try await call("get-users", .object(body), auth: true, fetchOptions: fo)
    }

    // ---- tickets --------------------------------------------------------------------------------

    /// Calls a ticket of the project (set up on skapi.com) with `data`. Returns its receipt or answer.
    @discardableResult
    public func consumeTicket(ticketId: String, method: String = "POST", data: JSON? = nil, auth: Bool = false) async throws -> JSON {
        try await ensureConnection()
        if ticketId.isEmpty { throw paramError("Ticket ID is required.") }
        if !Rx.match("^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$", ticketId) {
            throw paramError("Invalid \"ticket_id\". Use letters, digits, \"_\" and \"-\" (up to 64 chars, starting with a letter or digit).")
        }
        if method.isEmpty { throw paramError("Method is required. Should be either \"GET\" or \"POST\"") }
        let method = method.uppercased()
        if method != "GET" && method != "POST" { throw paramError("Method should be either \"GET\" or \"POST\".") }
        if auth && method == "GET" { throw paramError("Signed-in consumption is POST only.") }
        let route = auth ? "tpa" : (method == "GET" ? "tg" : "tp")
        let url = "https://\(service.prefix(4)).skapi.dev/\(route)/\(service)/\(ticketId)"
        let token = auth ? try await freshIdToken() : nil
        let body: JSON = (data?.truthy ?? false) ? data! : .object(JSONObject())
        let reply = try await requester.request(url, body, method: method, token: token, ignoreService: true)
        if let o = reply.object, o.contains("stage") {
            throw SkapiError(o["message"]?.string ?? "Ticket failed.", code: o["code"]?.string ?? "ERROR", cause: reply)
        }
        if let o = reply.object, o["tkid"]?.isString == true { return .object(mapTicket(o)) }
        return reply
    }
}
