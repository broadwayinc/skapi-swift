import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// One HTTP answer.
struct HTTPAnswer {
    let status: Int
    let headers: [String: String]  // lowercased names
    let body: Data
}

/// A network failure (no answer at all).
struct NetworkFailure: Error {
    let underlying: Error

    /// TIMEOUT when nothing moved for `timeout` seconds (URLRequest.timeoutInterval is an idle limit),
    /// as skapi-js 2.4.4 does ("No response for 60 seconds."); ABORTED when the calling Task was
    /// cancelled (skapi-js 2.7.0 `signal`); NETWORK_ERROR for any other failure.
    func skapiError(timeout: TimeInterval) -> SkapiError {
        if (underlying as? URLError)?.code == .cancelled || underlying is CancellationError {
            return SkapiError("Aborted", code: "ABORTED", cause: underlying)
        }
        if (underlying as? URLError)?.code == .timedOut {
            return SkapiError("No response for \(Int(timeout)) seconds.", code: "TIMEOUT", cause: underlying)
        }
        return SkapiError("Network error", code: "NETWORK_ERROR", cause: underlying)
    }
}

enum HTTP {
    /// Cancelling the calling Task cancels the request on the network too (it then fails with
    /// URLError.cancelled, which the callers report as ABORTED).
    static func send(_ request: URLRequest, session: URLSession = .shared) async throws -> HTTPAnswer {
        if Task.isCancelled { throw NetworkFailure(underlying: CancellationError()) }
        let holder = DataTaskHolder()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<HTTPAnswer, Error>) in
            let task = session.dataTask(with: request) { data, response, error in
                if let error = error {
                    cont.resume(throwing: NetworkFailure(underlying: error))
                    return
                }
                guard let http = response as? HTTPURLResponse else {
                    cont.resume(throwing: NetworkFailure(underlying: URLError(.badServerResponse)))
                    return
                }
                var headers: [String: String] = [:]
                for (k, v) in http.allHeaderFields {
                    if let k = k as? String { headers[k.lowercased()] = "\(v)" }
                }
                cont.resume(returning: HTTPAnswer(status: http.statusCode, headers: headers, body: data ?? Data()))
            }
            holder.set(task)
            task.resume()
            }
        } onCancel: {
            holder.cancel()
        }
    }
}

/// The data task of one HTTP.send, so a Task cancellation can reach it.
private final class DataTaskHolder: @unchecked Sendable {
    private let lock = NSLock()
    private var task: URLSessionDataTask?
    private var cancelled = false

    func set(_ t: URLSessionDataTask) {
        let cancelNow: Bool = lock.locked {
            task = t
            return cancelled
        }
        if cancelNow { t.cancel() }
    }

    func cancel() {
        let t: URLSessionDataTask? = lock.locked {
            cancelled = true
            return task
        }
        t?.cancel()
    }
}

/// encodeURIComponent.
func encodeURIComponent(_ s: String) -> String {
    var allowed = CharacterSet.alphanumerics.intersection(CharacterSet(charactersIn: Unicode.Scalar(0)...Unicode.Scalar(127)))
    allowed.insert(charactersIn: "-_.!~*'()")
    return s.addingPercentEncoding(withAllowedCharacters: allowed) ?? s
}

/// The request layer: endpoint discovery, headers, body encoding, errors, rate-limit retries and
/// paging, matching skapi-js (src/utils/network.ts) and skapi-py (_http.py).
final class Requester: @unchecked Sendable {
    static let defaultTargetCDN = "d3e9syvbtso631"
    static let endpointVersion = "v2"
    static let knownErrorCodes = ["INVALID_CORS", "INVALID_REQUEST", "SERVICE_DISABLED", "INVALID_PARAMETER", "ERROR", "EXISTS", "NOT_EXISTS"]
    static let rateLimitMaxRetries = 6

    static let adminRoundRobin: Set<String> = [
        "get-newsletters", "get-public-newsletters", "subscribe-newsletter", "subscribe-public-newsletter",
        "signupkey", "admin-newsletter-request", "admin-signup", "confirm-signup", "openid-logger",
        "block-account", "admin-edit-profile", "remove-account", "recover-account", "mock",
        "grant-access", "last-verified-email", "ticket", "register-ticket", "get-newsletter-subscription",
        "send-inquiry", "register-newsletter-group", "delete-newsletter-group", "newsletter-group-endpoint",
        "invitation-list", "csr", "csr-poll", "csr-cancel", "csr-finalize",
    ]
    static let recordRoundRobin: Set<String> = [
        "store-subscription", "get-vapid-public-key", "push-notification", "delete-subscription",
        "subscription", "get-subscription", "get-table", "get-tag", "get-uniqueid", "get-index",
        "get-signed-url", "get-signed-urls", "extract-file-text", "grid-query", "anonymous-login",
        "anonymous-session", "grant-private-access", "request-private-access-key", "get-ws-group",
        "check-schema", "get-feed", "castspell", "dopamine", "getspell",
    ]

    private static let counterLock = NSLock()
    private static var counter = 0  // one counter for admin and record picks, as in skapi-js
    private static func nextCounter() -> Int {
        counterLock.locked {
            counter += 1
            return counter
        }
    }

    let service: String
    let owner: String
    let version: String
    let targetCDN: String
    let timeout: TimeInterval
    let session: URLSession
    var publicIdentifier = ""

    private let lock = NSLock()
    private var admin: JSONObject?
    private var record: JSONObject?
    /// paging: the startKeys a query has seen, newest last ("end" when the list is done)
    private var startKeyHistory: [String: [String: [String]]] = [:]

    init(service: String, owner: String, version: String, targetCDN: String?, timeout: TimeInterval, session: URLSession) {
        self.service = service
        self.owner = owner
        self.version = version
        self.targetCDN = targetCDN ?? Requester.defaultTargetCDN
        self.timeout = timeout
        self.session = session
    }

    func clearStartKeyHistory() {
        lock.locked { startKeyHistory.removeAll() }
    }

    // ---- endpoints ------------------------------------------------------------------------------

    private func fetchEndpointFile(_ name: String) async throws -> JSONObject {
        let url = URL(string: "https://\(targetCDN).cloudfront.net/\(service.prefix(4))/\(name)-\(Requester.endpointVersion).json")!
        var req = URLRequest(url: url)
        req.timeoutInterval = timeout
        let answer: HTTPAnswer
        do {
            answer = try await HTTP.send(req, session: session)
        } catch let e as NetworkFailure {
            throw e.skapiError(timeout: timeout)
        }
        // Only the CDN's "no such file" (403 or 404) means the project does not exist. Anything else is
        // a failure on the way, reported with a code a caller (and a poll) retries: before, a passing
        // CDN error or a cut-off answer said "The project ID does not exist", and the next call, which
        // fetches the list again, worked.
        if answer.status == 403 || answer.status == 404 {
            throw SkapiError("The project ID does not exist. Create your project from skapi.com", code: "NOT_EXISTS")
        }
        if answer.status == 429 {
            throw SkapiError("Too many requests", code: "RATE_LIMITED")
        }
        guard (200..<300).contains(answer.status) else {
            throw SkapiError("Server error \(answer.status).", code: "SERVER_ERROR")
        }
        guard let v = try? JSON.parse(answer.body), let o = v.object else {
            throw SkapiError("Network error: the project's endpoint list \"\(name)\" arrived incomplete.", code: "NETWORK_ERROR")
        }
        return o
    }

    func endpoints() async throws -> (admin: JSONObject, record: JSONObject) {
        let (a, r) = lock.locked { (admin, record) }
        if let a = a, let r = r { return (a, r) }
        var na: JSONObject, nr: JSONObject
        if let x = a { na = x } else { na = try await fetchEndpointFile("admin") }
        if let x = r { nr = x } else { nr = try await fetchEndpointFile("record") }
        return lock.locked {
            admin = admin ?? na
            record = record ?? nr
            return (admin!, record!)
        }
    }

    private func selectGateway(_ kind: String, auth: Bool, stable: Bool) async throws -> String {
        let (admin, record) = try await endpoints()
        let n = Requester.nextCounter()
        if kind == "admin" {
            let suffix = auth ? "_private" : "_public"
            let items = admin.compactMap { (k, v) -> String? in
                (k.contains(suffix) && k != "get_users_private" && k != "service_public") ? v.string : nil
            }
            if items.isEmpty { throw SkapiError("No available admin gateways.", code: "INVALID_REQUEST") }
            return items[n % items.count]
        }
        let prefix = auth ? "record_private" : "record_public"
        let items = record.compactMap { (k, v) -> String? in k.contains(prefix) ? v.string : nil }
        if items.isEmpty { throw SkapiError("No available record gateways.", code: "INVALID_REQUEST") }
        if stable { return items[0] }
        return items[n % items.count]
    }

    func endpointURL(_ dest: String, auth: Bool, stable: Bool = false) async throws -> String {
        let (admin, record) = try await endpoints()
        var path = dest, query = ""
        if let q = dest.firstIndex(of: "?") {
            path = String(dest[..<q])
            query = String(dest[q...])
        }
        let base: String
        func need(_ o: JSONObject, _ k: String) throws -> String {
            guard let s = o[k]?.string else { throw SkapiError("No available gateway for \"\(path)\".", code: "INVALID_REQUEST") }
            return s
        }
        if path == "get-users" { base = try need(admin, "get_users_private") }
        else if path == "service" { base = try need(admin, "service_public") }
        else if Requester.adminRoundRobin.contains(path) { base = try await selectGateway("admin", auth: auth, stable: false) }
        else if path == "post-record" { base = try need(record, auth ? "post_private" : "post_public") }
        else if path == "get-records" { base = try need(record, auth ? "get_private" : "get_public") }
        else if path == "del-files" || path == "del-records" { base = try need(record, "del_private") }
        else if Requester.recordRoundRobin.contains(path) { base = try await selectGateway("record", auth: auth, stable: stable) }
        else {
            if !(path.hasPrefix("https://") || path.hasPrefix("http://")) {
                throw paramError("\"\(dest)\" is not a valid url.")
            }
            return dest
        }
        return base + path + query
    }

    // ---- request ----------------------------------------------------------------------------------

    /// One call. data: the body (an object is merged over {service, owner}); token: the fresh idToken
    /// when signed in; fetchOptions: limit, startKey, ascending (sent) and fetchMore (paging, not sent).
    func request(_ dest: String, _ data: JSON? = nil, auth: Bool = false, method: String = "POST", token: String? = nil,
                 fetchOptions: JSONObject? = nil, ignoreService: Bool = false, stableGateway: Bool = false,
                 contentType: String? = "application/json", extraHeaders: [String: String]? = nil) async throws -> JSON {
        let raw = try await requestRaw(dest, data, auth: auth, method: method, token: token, fetchOptions: fetchOptions,
                                       ignoreService: ignoreService, stableGateway: stableGateway, contentType: contentType,
                                       extraHeaders: extraHeaders, raw: false)
        return raw.json
    }

    struct Result {
        var json: JSON
        var bytes: Data
    }

    func requestRaw(_ dest: String, _ data: JSON?, auth: Bool, method methodIn: String, token: String?, fetchOptions: JSONObject?,
                    ignoreService: Bool, stableGateway: Bool, contentType: String?, extraHeaders: [String: String]?,
                    raw: Bool) async throws -> Result {
        let method = methodIn.uppercased()
        var url = try await endpointURL(dest, auth: auth, stable: stableGateway)
        let dataObj = data?.object
        let service = dataObj?["service"]?.string.flatMap { $0.isEmpty ? nil : $0 } ?? self.service
        let owner = dataObj?["owner"]?.string.flatMap { $0.isEmpty ? nil : $0 } ?? self.owner

        var fo = fetchOptions ?? JSONObject()
        let fetchMoreValue = fo.removeValue(forKey: "fetchMore") ?? fo.removeValue(forKey: "fetch_more")
        var fetchMore = fetchMoreValue.truthy
        if fo.contains("start_key") && !fo.contains("startKey") { fo["startKey"] = fo.removeValue(forKey: "start_key") }
        var sent = JSONObject()
        if let limit = fo["limit"], !limit.isNull {
            guard let n = limit.number else { throw SkapiError("Fetch limit should be a number.", code: "INVALID_REQUEST") }
            if n > 1000 { throw SkapiError("Fetch limit should be below 1000.", code: "INVALID_REQUEST") }
            sent["limit"] = limit
        }
        if let sk = fo["startKey"], !sk.isNull { sent["startKey"] = sk }
        if let asc = fo["ascending"], !asc.isNull {
            guard asc.isBool else { throw paramError("\"ascending\" should be a boolean.") }
            sent["ascending"] = asc
        }

        var body: JSON
        if ignoreService { body = .object(JSONObject()) } else { body = ["service": .string(service), "owner": .string(owner)] }
        for (k, v) in sent { body[k] = v }
        if let o = dataObj {
            for (k, v) in o { body[k] = v }
        } else if let d = data, d.truthy {
            body = d
        }

        // paging: a query asked again with fetchMore continues from the last startKey it got
        var historyKey: String?
        if case .object(var bo) = body {
            if let startKey = bo["startKey"], startKey.truthy {
                if startKey == .string("start") {
                    bo["startKey"] = nil
                    fetchMore = false
                } else if !(startKey == .string("end") || (startKey.object.map { !$0.isEmpty } ?? false)) {
                    throw paramError("\"\(startKey.pyString)\" is invalid startKey key.")
                }
            }
            let fingerprint = "\(method):\(auth ? "auth" : "public"):\(dest)"
            // the private key of a shared record is attached once this client has it (after page 1),
            // so it stays out of the paging key: the next page of the same query continues the same list
            var params = JSONObject()
            for (k, v) in bo where k != "startKey" && k != "private_key" { params[k] = v }
            let hk = Prim.md5Hex(fingerprint + "/" + sortedKeys(.object(params)).jsonString)
            historyKey = hk
            let seenBefore: [String]? = lock.locked {
                var history = startKeyHistory[dest] ?? [:]
                if !fetchMore {
                    history[hk] = nil
                    startKeyHistory[dest] = history
                    return nil
                }
                return history[hk]
            }
            if let seen = seenBefore, let last = seen.last {
                if last == "end" {
                    return Result(json: ["list": [], "startKey": "end", "endOfList": true,
                                         "startKeyHistory": .array(seen.map { .string($0) })], bytes: Data())
                }
                bo["startKey"] = try JSON.parse(last)
            }
            body = .object(bo)
        }

        var headers: [String: String] = ["Accept": "*/*"]
        if let ct = contentType { headers["Content-Type"] = ct }
        if let t = token { headers["Authorization"] = t }
        for (k, v) in extraHeaders ?? [:] { headers[k] = v }
        headers["Content-Meta"] = contentMeta(service: service, owner: owner)

        var payload: Data?
        if method == "GET" {
            if let o = body.object, !o.isEmpty {
                let pairs = o.map { (k, v) in encodeURIComponent(k) + "=" + encodeURIComponent(v.string ?? v.jsonString) }
                    .joined(separator: "&")
                if !url.contains("?") { url += "?" }
                else if !(url.hasSuffix("?") || url.hasSuffix("&")) { url += "&" }
                url += pairs
            }
        } else if case .string(let s) = body {
            payload = Data(s.utf8)
        } else if body.truthy {
            payload = Data(body.jsonString.utf8)
        }

        var result = try await send(url: url, method: method, headers: headers, payload: payload, raw: raw)

        if let hk = historyKey, let o = result.json.object, let sk = o["startKey"], sk.truthy {
            let entry = sk == .string("end") ? "end" : sk.jsonString
            let seen: [String] = lock.locked {
                var history = startKeyHistory[dest] ?? [:]
                var seen = history[hk] ?? []
                if !seen.contains(entry) { seen.append(entry) }
                history[hk] = seen
                startKeyHistory[dest] = history
                return seen
            }
            var out = JSONObject()
            out["startKeyHistory"] = .array(seen.map { .string($0) })
            for (k, v) in o where k != "startKeyHistory" { out[k] = v }
            if o.contains("startKeyHistory") { out["startKeyHistory"] = o["startKeyHistory"] }
            result.json = .object(out)
        }
        return result
    }

    /// The Content-Meta header every request carries, as skapi-js writes it.
    func contentMeta(service: String, owner: String) -> String {
        let meta: JSON = [
            "public_identifier": .string(publicIdentifier),
            "service": .string(service),
            "owner": .string(owner),
            "resolves_offloaded_data": true,
            "skapi_version": .string(version),
            "expiring_private_keys": true,  // renews private access keys before they expire, so 1-hour keys are safe
        ]
        return meta.jsonString
    }

    /// `uploadName`: set by `upload`, so a stalled upload is reported as TIMEOUT. URLRequest's
    /// timeoutInterval is an idle limit (it restarts whenever bytes move, upload bytes included) and
    /// URLSession.shared allows 7 days in total, so a slow upload that keeps moving is never cut off.
    func send(url: String, method: String, headers: [String: String], payload: Data?, raw: Bool = false,
              uploadName: String? = nil) async throws -> Result {
        guard let u = URL(string: url) else { throw paramError("\"\(url)\" is an invalid url.") }
        var attempt = 0
        while true {
            var req = URLRequest(url: u)
            req.httpMethod = method
            req.timeoutInterval = timeout
            for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
            req.httpBody = payload
            let answer: HTTPAnswer
            do {
                answer = try await HTTP.send(req, session: session)
            } catch let e as NetworkFailure {
                if let name = uploadName, (e.underlying as? URLError)?.code == .timedOut {
                    throw SkapiError("Upload timeout: \"\(name)\" stalled (nothing moved for \(Int(timeout)) seconds).",
                                     code: "TIMEOUT", cause: e.underlying)
                }
                throw e.skapiError(timeout: timeout)
            }
            if (200..<300).contains(answer.status) {
                if raw { return Result(json: .null, bytes: answer.body) }
                let text = String(decoding: answer.body, as: UTF8.self)
                if let v = try? JSON.parse(answer.body) { return Result(json: v, bytes: answer.body) }
                return Result(json: .string(text), bytes: answer.body)
            }
            let text = String(decoding: answer.body, as: UTF8.self)
            if answer.status == 429 {
                guard let delay = Requester.retryDelayMs(answer.headers["retry-after"]) else {
                    // a 429 that carries its own error (a ticket whose slots are all taken) keeps it
                    if !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                        let carried = Requester.parseError(status: 429, text: text)
                        if carried.code != "ERROR" && carried.code != "429" { throw carried }
                    }
                    // skapi-js 2.7.0: RATE_LIMITED on the request path; an upload says TOO_MANY_REQUESTS
                    // (skapi-js toFileUploadError).
                    throw SkapiError("Too many requests", code: uploadName == nil ? "RATE_LIMITED" : "TOO_MANY_REQUESTS")
                }
                if attempt >= Requester.rateLimitMaxRetries {
                    let bare = url.split(separator: "?", maxSplits: 1).first.map(String.init) ?? url
                    throw SkapiError("Too many requests: \"\(bare)\" still answered 429 after \(Requester.rateLimitMaxRetries) retries.",
                                     code: "TOO_MANY_REQUESTS")
                }
                do {
                    try await Task.sleep(nanoseconds: UInt64(Requester.rateLimitWaitMs(delay, attempt: attempt) * 1_000_000))
                } catch {
                    throw abortedError()  // cancelled while waiting out Retry-After: ABORTED, as any cancel
                }
                attempt += 1
                continue
            }
            // A server fault, not a refusal (skapi-js 2.7.0): SERVER_ERROR whatever the body says, so a
            // caller can tell "try again" from "no". Uploads keep the storage service's own code, as in
            // skapi-js.
            if uploadName == nil { throw Requester.serverFault(status: answer.status, text: text) ?? Requester.parseError(status: answer.status, text: text) }
            throw Requester.parseError(status: answer.status, text: text)
        }
    }

    /// SERVER_ERROR for a 5xx answer other than 501 (which says the route does not exist here, an
    /// answer), with the body kept as the cause; nil for any other status.
    static func serverFault(status: Int, text: String) -> SkapiError? {
        guard status >= 500 && status != 501 else { return nil }
        let body = (try? JSON.parse(text)) ?? .string(text)
        if case .string(let s) = body {
            let parts = s.components(separatedBy: ":")
            let message = parts.dropFirst().joined(separator: ":").trimmingCharacters(in: .whitespacesAndNewlines)
            let shown = !message.isEmpty ? message : (!s.isEmpty ? s : "Server error \(status).")
            return SkapiError(shown, code: "SERVER_ERROR", cause: body)
        }
        if let o = body.object, o.contains("message") || o.contains("stage") || o.contains("code") {
            var message = (o["message"]?.string ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            if message.isEmpty { message = o["code"].flatMap { $0.truthy ? $0.pyString : nil } ?? String(status) }
            return SkapiError(message, code: "SERVER_ERROR", cause: o["cause"] ?? body)
        }
        return SkapiError("Server error \(status).", code: "SERVER_ERROR", cause: body)
    }

    static func retryDelayMs(_ value: String?) -> Double? {
        guard let value = value?.trimmingCharacters(in: .whitespaces), !value.isEmpty else { return nil }
        if let s = Double(value) { return max(0, s * 1000) }
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "GMT")
        f.dateFormat = "EEE, dd MMM yyyy HH:mm:ss zzz"
        if let d = f.date(from: value) { return max(0, d.timeIntervalSinceNow * 1000) }
        return nil
    }

    static func rateLimitWaitMs(_ delay: Double, attempt: Int) -> Double {
        var base = delay > 0 ? delay : min(60000, 500 * pow(2, Double(attempt)))
        base = min(60000, base)
        return base + floor(Double.random(in: 0..<1) * min(1000, max(50, base * 0.25)))
    }

    /// A non-2xx answer as a SkapiError, read the way skapi-js reads it.
    static func parseError(status: Int, text: String) -> SkapiError {
        let body = (try? JSON.parse(text)) ?? .string(text)
        if case .string(let s) = body {
            let parts = s.components(separatedBy: ":")
            let code = parts[0].trimmingCharacters(in: .whitespacesAndNewlines)
            let message = parts.dropFirst().joined(separator: ":").trimmingCharacters(in: .whitespacesAndNewlines)
            return SkapiError(message.isEmpty ? s : message, code: knownErrorCodes.contains(code) ? code : "ERROR")
        }
        if let o = body.object, o.contains("message") || o.contains("stage") || o.contains("code") {
            var code = o["code"].flatMap { $0.truthy ? $0.pyString : nil } ?? String(status)
            if code.isEmpty { code = "ERROR" }
            var message = (o["message"]?.string ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            if message.isEmpty { message = code }
            let cause: JSON? = o["cause"] ?? (o.contains("stage") ? body : nil)
            return SkapiError(message, code: code, cause: cause)
        }
        return SkapiError(body.pyString, code: "ERROR")
    }

    /// A plain GET with no extra headers: for pre-signed links, whose signature covers the headers.
    func fetchPlain(_ url: String) async throws -> Data {
        guard let u = URL(string: url) else { throw paramError("\"\(url)\" is an invalid url.") }
        var req = URLRequest(url: u)
        req.timeoutInterval = timeout
        let answer: HTTPAnswer
        do {
            answer = try await HTTP.send(req, session: session)
        } catch let e as NetworkFailure {
            throw e.skapiError(timeout: timeout)
        }
        if (200..<300).contains(answer.status) { return answer.body }
        let text = String(decoding: answer.body, as: UTF8.self)
        func tag(_ name: String) -> String? {
            guard let a = text.range(of: "<\(name)>"), let b = text.range(of: "</\(name)>", range: a.upperBound..<text.endIndex) else { return nil }
            return String(text[a.upperBound..<b.lowerBound])
        }
        let code = tag("Code"), message = tag("Message")
        if code != nil || message != nil {
            throw SkapiError(message ?? String(text.prefix(300)), code: code ?? "ERROR")
        }
        throw Requester.parseError(status: answer.status, text: text)
    }

    /// multipart/form-data POST to a signed upload URL: every field in order, then the file.
    func upload(url: String, fields: JSONObject, filename: String, content: Data, contentType: String?) async throws {
        let boundary = "----skapi" + Prim.md5Hex(String(Double.random(in: 0..<1)))
        var body = Data()
        for (k, v) in fields {
            body += Data("--\(boundary)\r\nContent-Disposition: form-data; name=\"\(k)\"\r\n\r\n\(v.string ?? v.jsonString)\r\n".utf8)
        }
        let safe = filename.replacingOccurrences(of: "\"", with: "%22").replacingOccurrences(of: "\r", with: "")
            .replacingOccurrences(of: "\n", with: "")
        body += Data(("--\(boundary)\r\nContent-Disposition: form-data; name=\"file\"; filename=\"\(safe)\"\r\n" +
                      "Content-Type: \(contentType ?? "application/octet-stream")\r\n\r\n").utf8)
        body += content
        body += Data("\r\n--\(boundary)--\r\n".utf8)
        _ = try await send(url: url, method: "POST", headers: ["Content-Type": "multipart/form-data; boundary=\(boundary)"], payload: body,
                           uploadName: filename)
    }
}

/// Every object's keys sorted (for the paging fingerprint).
func sortedKeys(_ v: JSON) -> JSON {
    switch v {
    case .object(let o):
        var out = JSONObject()
        for k in o.keys.sorted() { out[k] = sortedKeys(o[k]!) }
        return .object(out)
    case .array(let a): return .array(a.map(sortedKeys))
    default: return v
    }
}

extension NSLocking {
    /// Runs body while holding the lock (usable from async code, unlike lock() and unlock()).
    @discardableResult
    func locked<T>(_ body: () throws -> T) rethrows -> T {
        lock()
        defer { unlock() }
        return try body()
    }
}
