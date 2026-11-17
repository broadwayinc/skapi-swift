import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// An error answered by the user pool API, or a network failure (code "NetworkError").
struct CognitoError: Error {
    let message: String?
    let code: String
    let status: Int?
}

/// A sign-in step that needs one more answer (new password, authenticator code).
struct Challenge: Error {
    let name: String
    let parameters: JSONObject
    let session: String?
}

/// A JWT, with its payload decoded (the signature is the server's to check).
public struct JwtToken: Sendable {
    public let jwtToken: String
    public let payload: JSONObject

    init(_ token: String?) {
        jwtToken = token ?? ""
        let parts = jwtToken.split(separator: ".", omittingEmptySubsequences: false)
        if parts.count > 1, let v = try? JSON.parse(B64.any(String(parts[1]))), let o = v.object {
            payload = o
        } else {
            payload = JSONObject()
        }
    }

    public var expiration: Double { payload["exp"]?.number ?? 0 }
    public var issuedAt: Double { payload["iat"]?.number ?? 0 }
}

/// The signed-in session's tokens.
public struct SkapiSession: Sendable {
    public let idToken: JwtToken
    public let accessToken: JwtToken
    public let refreshToken: String
    let clockDrift: Int

    init(idToken: String?, accessToken: String?, refreshToken: String?, clockDrift: Int? = nil) {
        self.idToken = JwtToken(idToken)
        self.accessToken = JwtToken(accessToken)
        self.refreshToken = refreshToken ?? ""
        // seconds this device's clock is ahead of the token issuer's, measured when the tokens arrive
        self.clockDrift = clockDrift ?? (Int(Date().timeIntervalSince1970) - Int(min(self.accessToken.issuedAt, self.idToken.issuedAt)))
    }

    var isValid: Bool {
        let adjusted = Double(Int(Date().timeIntervalSince1970) - clockDrift)
        return adjusted < accessToken.expiration && adjusted < idToken.expiration
    }
}

/// The user pool API (cognito-idp), as skapi-js and skapi-py call it.
struct CognitoClient {
    static let requestTimeout: TimeInterval = 60
    let endpoint: URL
    let session: URLSession

    init(region: String, session: URLSession) {
        endpoint = URL(string: "https://cognito-idp.\(region).amazonaws.com/")!
        self.session = session
    }

    /// One call. Keys whose value is nil are left out, as JSON.stringify drops undefined.
    func request(_ operation: String, _ params: JSONObject) async throws -> JSONObject {
        var req = URLRequest(url: endpoint)
        req.httpMethod = "POST"
        req.timeoutInterval = CognitoClient.requestTimeout
        req.setValue("application/x-amz-json-1.1", forHTTPHeaderField: "Content-Type")
        req.setValue("AWSCognitoIdentityProviderService.\(operation)", forHTTPHeaderField: "X-Amz-Target")
        req.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        req.httpBody = Data(JSON.object(params).jsonString.utf8)
        let answer: HTTPAnswer
        do {
            answer = try await HTTP.send(req, session: session)
        } catch {
            throw CognitoError(message: "Network error", code: "NetworkError", status: nil)
        }
        let data = (try? JSON.parse(answer.body))?.object ?? JSONObject()
        if (200..<300).contains(answer.status) { return data }
        if let kind = (data["__type"] ?? data["code"])?.string, !kind.isEmpty {
            let code = kind.components(separatedBy: "#").last ?? kind
            throw CognitoError(message: data["message"]?.string ?? data["Message"]?.string, code: code, status: answer.status)
        }
        if let header = answer.headers["x-amzn-errortype"] {
            throw CognitoError(message: String(answer.status), code: header.components(separatedBy: ":")[0], status: answer.status)
        }
        throw CognitoError(message: String(answer.status), code: "UnknownError", status: answer.status)
    }

    /// request() with jittered exponential retries on ANY error, as skapi-js does for a token refresh:
    /// waits of about 0.2, 0.4, 0.8, 1.6 and 3.2 seconds, then gives up when the next would pass 5 s.
    func requestWithRetry(_ operation: String, _ params: JSONObject) async throws -> JSONObject {
        var attempt = 1
        while true {
            do {
                return try await request(operation, params)
            } catch let e as CognitoError {
                let delay = pow(2, Double(attempt)) * 100 + 100 * Double.random(in: 0..<1)
                if delay > 5000 { throw e }
                try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000))
                attempt += 1
            }
        }
    }
}

/// The user pool, as skapi-swift uses it. Sign-in is SRP only: the password never leaves the device.
/// No device tracking (off on every Skapi user pool) and no text messages of any kind.
final class UserPool: @unchecked Sendable {
    let userPoolId: String
    let clientId: String
    let poolName: String
    let client: CognitoClient
    let storage: SkapiStorage
    let keyPrefix: String

    init(userPoolId: String, clientId: String, storage: SkapiStorage, session: URLSession) throws {
        let parts = userPoolId.components(separatedBy: "_")
        guard !userPoolId.isEmpty, !clientId.isEmpty, parts.count >= 2 else {
            throw SkapiError("Both UserPoolId and ClientId are required.", code: "ERROR")
        }
        self.userPoolId = userPoolId
        self.clientId = clientId
        poolName = parts[1]
        client = CognitoClient(region: parts[0], session: session)
        self.storage = storage
        keyPrefix = "CognitoIdentityServiceProvider.\(clientId)"
    }

    // -- storage --------------------------------------------------------------------------------

    func lastAuthUser() -> String? { storage.getItem("\(keyPrefix).LastAuthUser") }

    func cacheTokens(_ username: String, _ s: SkapiSession) {
        let p = "\(keyPrefix).\(username)"
        storage.setItem("\(p).idToken", s.idToken.jwtToken)
        storage.setItem("\(p).accessToken", s.accessToken.jwtToken)
        storage.setItem("\(p).refreshToken", s.refreshToken)
        storage.setItem("\(p).clockDrift", String(s.clockDrift))
        storage.setItem("\(keyPrefix).LastAuthUser", username)
    }

    func clearCachedTokens(_ username: String) {
        let p = "\(keyPrefix).\(username)"
        for k in ["\(p).idToken", "\(p).accessToken", "\(p).refreshToken", "\(keyPrefix).LastAuthUser", "\(p).clockDrift", "\(p).userData"] {
            storage.removeItem(k)
        }
    }

    func cachedSession(_ username: String) -> SkapiSession? {
        let p = "\(keyPrefix).\(username)"
        guard let id = storage.getItem("\(p).idToken"), !id.isEmpty else { return nil }
        let drift = Int(storage.getItem("\(p).clockDrift") ?? "0") ?? 0
        return SkapiSession(idToken: id, accessToken: storage.getItem("\(p).accessToken") ?? "",
                            refreshToken: storage.getItem("\(p).refreshToken") ?? "", clockDrift: drift)
    }

    static func session(from result: JSONObject?, refreshToken: String? = nil) -> SkapiSession {
        let r = result ?? JSONObject()
        let rt = r["RefreshToken"]?.string
        return SkapiSession(idToken: r["IdToken"]?.string, accessToken: r["AccessToken"]?.string,
                            refreshToken: (rt?.isEmpty == false) ? rt : refreshToken)
    }

    // -- sign-up and sign-in -------------------------------------------------------------------

    func signUp(username: String, password: String, attributes: [JSON]) async throws -> JSONObject {
        try await client.request("SignUp", [
            "ClientId": .string(clientId),
            "Username": .string(username),
            "Password": .string(password),
            "UserAttributes": .array(attributes),
        ])
    }

    /// SRP sign-in. Returns (username for SRP, session), or throws Challenge for a next step
    /// (NEW_PASSWORD_REQUIRED, SOFTWARE_TOKEN_MFA, ...) and CognitoError for a refusal.
    func authenticate(username: String, password: String) async throws -> (String, SkapiSession) {
        let helper = try SRP.Helper(poolName: poolName)
        let data = try await client.request("InitiateAuth", [
            "AuthFlow": "USER_SRP_AUTH",
            "ClientId": .string(clientId),
            "AuthParameters": ["USERNAME": .string(username), "SRP_A": .string(helper.largeA.hex)],
            "ClientMetadata": [:],
        ])
        let params = data["ChallengeParameters"]?.object ?? JSONObject()
        let srpUsername = params["USER_ID_FOR_SRP"]?.string ?? ""
        let secretBlock = params["SECRET_BLOCK"]?.string ?? ""
        let key = try helper.passwordAuthenticationKey(username: srpUsername, password: password,
                                                       serverB: SRP.hexToInt(params["SRP_B"]?.string ?? ""),
                                                       salt: SRP.hexToInt(params["SALT"]?.string ?? ""))
        let now = SRP.cognitoTimestamp()
        let signature = SRP.signature(key: key, poolName: poolName, username: srpUsername, secretBlock: secretBlock, timestamp: now)
        var body: JSONObject = [
            "ChallengeName": "PASSWORD_VERIFIER",
            "ClientId": .string(clientId),
            "ChallengeResponses": [
                "USERNAME": .string(srpUsername),
                "PASSWORD_CLAIM_SECRET_BLOCK": .string(secretBlock),
                "TIMESTAMP": .string(now),
                "PASSWORD_CLAIM_SIGNATURE": .string(signature),
            ],
        ]
        if let s = data["Session"]?.string { body["Session"] = .string(s) }
        body["ClientMetadata"] = [:]
        let answer = try await client.request("RespondToAuthChallenge", body)
        return (srpUsername, try finish(srpUsername, answer))
    }

    private func finish(_ username: String, _ answer: JSONObject) throws -> SkapiSession {
        if let name = answer["ChallengeName"]?.string, !name.isEmpty {
            if name == "DEVICE_SRP_AUTH" {
                throw CognitoError(message: "Device authentication is not supported.", code: "DeviceAuthenticationNotSupported", status: nil)
            }
            throw Challenge(name: name, parameters: answer["ChallengeParameters"]?.object ?? JSONObject(), session: answer["Session"]?.string)
        }
        let s = UserPool.session(from: answer["AuthenticationResult"]?.object)
        cacheTokens(username, s)
        return s
    }

    private func respond(_ body: JSONObject, session: String?) async throws -> JSONObject {
        var b = body
        if let s = session { b["Session"] = .string(s) }
        return try await client.request("RespondToAuthChallenge", b)
    }

    func completeNewPassword(username: String, newPassword: String, challengeSession: String?) async throws -> SkapiSession {
        let answer = try await respond([
            "ChallengeName": "NEW_PASSWORD_REQUIRED",
            "ClientId": .string(clientId),
            "ChallengeResponses": ["NEW_PASSWORD": .string(newPassword), "USERNAME": .string(username)],
        ], session: challengeSession)
        return try finish(username, answer)
    }

    func sendMFACode(username: String, code: String, challengeSession: String?) async throws -> SkapiSession {
        let answer = try await respond([
            "ChallengeName": "SOFTWARE_TOKEN_MFA",
            "ChallengeResponses": ["USERNAME": .string(username), "SMS_MFA_CODE": .string(code), "SOFTWARE_TOKEN_MFA_CODE": .string(code)],
            "ClientId": .string(clientId),
        ], session: challengeSession)
        return try finish(username, answer)
    }

    func selectMFAType(username: String, answerName: String, challengeSession: String?) async throws -> Challenge {
        let data = try await respond([
            "ChallengeName": "SELECT_MFA_TYPE",
            "ChallengeResponses": ["USERNAME": .string(username), "ANSWER": .string(answerName)],
            "ClientId": .string(clientId),
        ], session: challengeSession)
        return Challenge(name: data["ChallengeName"]?.string ?? answerName, parameters: data["ChallengeParameters"]?.object ?? JSONObject(),
                         session: data["Session"]?.string)
    }

    // -- session --------------------------------------------------------------------------------

    /// REFRESH_TOKEN_AUTH with retries. A NotAuthorizedException ends the stored session.
    func refresh(username usernameIn: String, refreshToken: String) async throws -> SkapiSession {
        var username = usernameIn
        var auth: JSONObject = ["REFRESH_TOKEN": .string(refreshToken)]
        if let last = lastAuthUser(), !last.isEmpty {
            username = last
            // sent as skapi-js sends it: null, since no device is ever remembered
            auth["DEVICE_KEY"] = storage.getItem("\(keyPrefix).\(username).deviceKey").map { .string($0) } ?? .null
        }
        let result: JSONObject
        do {
            result = try await client.requestWithRetry("InitiateAuth", [
                "ClientId": .string(clientId), "AuthFlow": "REFRESH_TOKEN_AUTH", "AuthParameters": .object(auth),
            ])
        } catch let e as CognitoError {
            if e.code == "NotAuthorizedException" { clearCachedTokens(username) }
            throw e
        }
        let s = UserPool.session(from: result["AuthenticationResult"]?.object, refreshToken: refreshToken)
        cacheTokens(username, s)
        return s
    }

    // -- calls made with the access token -----------------------------------------------------

    func call(_ operation: String, accessToken: String, _ params: JSONObject = [:]) async throws -> JSONObject {
        var p = params
        p["AccessToken"] = .string(accessToken)
        return try await client.request(operation, p)
    }

    func callPublic(_ operation: String, _ params: JSONObject = [:]) async throws -> JSONObject {
        var p = params
        p["ClientId"] = .string(clientId)
        return try await client.request(operation, p)
    }
}
