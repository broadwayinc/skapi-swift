import Foundation

/// Regular expressions, compiled once.
enum Rx {
    private static let lock = NSLock()
    private static var cache: [String: NSRegularExpression] = [:]

    static func re(_ pattern: String, _ options: NSRegularExpression.Options = []) -> NSRegularExpression {
        let key = pattern + "#\(options.rawValue)"
        lock.lock(); defer { lock.unlock() }
        if let r = cache[key] { return r }
        let r = try! NSRegularExpression(pattern: pattern, options: options)
        cache[key] = r
        return r
    }

    /// Python re.search.
    static func search(_ pattern: String, _ s: String, _ options: NSRegularExpression.Options = []) -> Bool {
        re(pattern, options).firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil
    }

    /// Python re.match (anchored at the start).
    static func match(_ pattern: String, _ s: String, _ options: NSRegularExpression.Options = []) -> Bool {
        re(pattern, options).firstMatch(
            in: s, options: [.anchored], range: NSRange(s.startIndex..., in: s)) != nil
    }

    /// The capture groups of the first match.
    static func groups(_ pattern: String, _ s: String, _ options: NSRegularExpression.Options = []) -> [String]? {
        guard let m = re(pattern, options).firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) else { return nil }
        return (0..<m.numberOfRanges).map { i in
            Range(m.range(at: i), in: s).map { String(s[$0]) } ?? ""
        }
    }

    /// Python re.sub with a replacement function.
    static func sub(_ pattern: String, _ s: String, _ options: NSRegularExpression.Options = [], _ f: ([String]) -> String) -> String {
        let r = re(pattern, options)
        var out = ""
        var last = s.startIndex
        for m in r.matches(in: s, range: NSRange(s.startIndex..., in: s)) {
            guard let whole = Range(m.range, in: s) else { continue }
            out += s[last..<whole.lowerBound]
            let gs = (0..<m.numberOfRanges).map { i in Range(m.range(at: i), in: s).map { String(s[$0]) } ?? "" }
            out += f(gs)
            last = whole.upperBound
        }
        out += s[last...]
        return out
    }
}

enum Check {
    static func isUUID(_ v: String) -> Bool { ProjectID.isUUID(v) }

    static func email(_ v: JSON?) throws -> String {
        guard let v = v, v.truthy else { throw paramError("\"email\" is required.") }
        guard let s = v.string else { throw paramError("\"email\" should be type: string.") }
        if s.unicodeScalars.count < 5 { throw paramError("\"email\" should be at least 5 characters.") }
        let trimmed = s.trimmingCharacters(in: .whitespacesAndNewlines)
        let domain = trimmed.components(separatedBy: "@").dropFirst().first ?? ""
        if !Rx.match("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\\.[a-zA-Z0-9-]+)*$", s)
            || domain.components(separatedBy: ".").count < 2 {
            throw paramError("\"\(s)\" is an invalid email.")
        }
        return trimmed.lowercased()
    }

    static func password(_ v: JSON?, field: String = "password") throws -> String {
        guard let v = v, v.truthy else { throw paramError("\"\(field)\" is required.") }
        guard let s = v.string else { throw paramError("\"\(field)\" should be type: string.") }
        if s.unicodeScalars.count < 6 { throw paramError("\"\(field)\" should be at least 6 characters.") }
        if s.unicodeScalars.count > 60 { throw paramError("\"\(field)\" can be up to 60 characters max.") }
        return s
    }

    static func phone(_ v: JSON) throws -> JSON {
        if !v.truthy { return "" }
        let err = paramError("\"phone_number\" is invalid. The format should be \"+00123456789\". Type: string.")
        guard let s = v.string, s.hasPrefix("+") else { throw err }
        var rest = String(s.dropFirst()).trimmingCharacters(in: .whitespacesAndNewlines)
        if let dot = rest.firstIndex(of: ".") { rest.remove(at: dot) }
        if rest.isEmpty || !rest.allSatisfy({ $0.isNumber }) { throw err }
        return v
    }

    static func birthdate(_ v: JSON) throws -> JSON {
        if !v.truthy { return "" }
        guard let s = v.string, s.count == 10, s.components(separatedBy: "-").count == 3,
              Rx.search("([12]\\d{3}-(0[1-9]|1[0-2])-(0[1-9]|[12]\\d|3[01]))", s) else {
            throw paramError("\"birthdate\" is invalid. The format should be \"yyyy-mm-dd\". Type: string.")
        }
        return v
    }

    /// Python urlsplit's scheme and netloc.
    static func splitURL(_ s: String) -> (scheme: String, netloc: String, path: String)? {
        guard let colon = s.firstIndex(of: ":") else { return nil }
        let scheme = String(s[..<colon])
        guard let f = scheme.first, f.isASCII, f.isLetter,
              scheme.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || "+-.".contains($0)) }) else { return nil }
        var rest = s[s.index(after: colon)...]
        var netloc = ""
        if rest.hasPrefix("//") {
            rest = rest.dropFirst(2)
            let end = rest.firstIndex(where: { "/?#".contains($0) }) ?? rest.endIndex
            netloc = String(rest[..<end])
            rest = rest[end...]
        }
        let pathEnd = rest.firstIndex(where: { "?#".contains($0) }) ?? rest.endIndex
        return (scheme.lowercased(), netloc, String(rest[..<pathEnd]))
    }

    static func url(_ v: JSON) throws -> JSON {
        if !v.truthy { return "" }
        guard let s = v.string else { throw paramError("\"\(v.pyString)\" is an invalid url.") }
        if s == "*" { return v }
        guard let parts = splitURL(s), !parts.scheme.isEmpty, !parts.netloc.isEmpty else {
            throw paramError("\"\(s)\" is an invalid url.")
        }
        return .string(parts.path.isEmpty ? s + "/" : s)
    }

    static func address(_ v: JSON) throws -> JSON {
        if !v.truthy { return "" }
        if v.isString { return v }
        if v.isObject { return .string(v.jsonString) }
        throw paramError("\"address\" should be type: <string | dict>.")
    }

    static func string(_ field: String) -> (JSON) throws -> JSON {
        { v in
            guard v.isString else { throw paramError("\(jd(v)) is invalid in \"\(field)\". allowed type or value is: Type<string>.") }
            return v
        }
    }

    static func boolean(_ field: String) -> (JSON) throws -> JSON {
        { v in
            guard v.isBool else { throw paramError("\(jd(v)) is invalid in \"\(field)\". allowed type or value is: Type<boolean>.") }
            return v
        }
    }

    static func mfaCode(_ v: String?) throws -> String {
        let code = (v ?? "").components(separatedBy: .whitespacesAndNewlines).joined()
        guard code.count == 6, code.allSatisfy({ $0.isASCII && $0.isNumber }) else {
            throw paramError("\"code\" should be the 6 digit code from the authenticator app.")
        }
        return code
    }
}

/// "#CODE: text" messages from the pool's triggers carry their own code.
func parsedCognitoError(_ err: CognitoError) -> SkapiError {
    let code = err.code.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "ERROR" : err.code.trimmingCharacters(in: .whitespacesAndNewlines)
    var message = (err.message ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
    if message.isEmpty { message = "An error occurred." }
    if let g = Rx.groups("#([A-Za-z0-9_]+)\\s*:\\s*([\\s\\S]+)", message) {
        return SkapiError(g[2].trimmingCharacters(in: .whitespacesAndNewlines), code: g[1].trimmingCharacters(in: .whitespacesAndNewlines), cause: err)
    }
    return SkapiError(message, code: code, cause: err)
}

/// The ID token's claims as the user profile skapi-js returns.
func parseUserAttributes(_ claims: JSONObject) -> JSONObject {
    let skip: Set<String> = ["aud", "cognito:username", "event_id", "exp", "iat", "iss", "jti", "origin_jti", "secret_key", "token_use"]
    let rename = ["auth_time": "log", "sub": "user_id"]
    var user = JSONObject()
    if let username = claims["cognito:username"]?.string {
        let parts = username.components(separatedBy: "-")
        if parts.count == 2 && parts[1].hasPrefix("anon") { user["anonymous"] = true }
    }
    for (k, v) in claims {
        if skip.contains(k) { continue }
        if let r = rename[k] { user[r] = v }
        else if k.contains("custom:") { user[k.replacingOccurrences(of: "custom:", with: "")] = v }
        else if k == "address" {
            if let o = v.object {
                if let f = o["formatted"], f.truthy {
                    if let s = f.string, let parsed = try? JSON.parse(s) { user["address"] = parsed } else { user["address"] = f }
                }
            } else {
                user["address"] = v
            }
        } else {
            user[k] = v
        }
    }
    for k in ["address_public", "birthdate_public", "email_public", "gender_public", "phone_number_public"] {
        let base = String(k.dropLast("_public".count))
        if user.contains(base) {
            let raw = user[k]
            var flag = false
            if let r = raw, r.truthy {
                if let n = r.number { flag = n != 0 }
                else if let s = r.string, let d = Double(s.trimmingCharacters(in: .whitespaces)) { flag = d != 0 }
                else if let b = r.bool { flag = b }
            }
            user[k] = .bool(flag)
        } else {
            user[k] = nil
        }
    }
    var group = 0
    if let g = user["access_group"], g.truthy {
        if let n = g.number { group = Int(n) }
        else if let s = g.string, let d = Double(s.trimmingCharacters(in: .whitespaces)) { group = Int(d) }
    }
    user["access_group"] = .number(Double(group))
    for k in ["email", "phone_number"] {
        if user.contains(k) {
            user["\(k)_verified"] = .bool(user["\(k)_verified"] == .bool(true))
        } else {
            user["\(k)_verified"] = nil
        }
    }
    return user
}
