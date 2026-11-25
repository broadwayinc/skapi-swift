import Foundation

/// One part of a multipart/form-data body for `forwardRequest` with `"multipart": true`.
public enum FormPart: Sendable {
    /// A text field: a string as it is, null as "", a boolean as "true"/"false", anything else as JSON.
    case field(String, JSON)
    /// A file part.
    case file(String, UploadFile)
    /// Bytes, sent as a file part named after the field.
    case data(String, Data)
}

/// Request forwarding (call another API through Skapi, with your stored client secrets) and
/// inquiries, ported from skapi-py (_forward.py) and skapi-js (src/methods/request.ts).
///
/// Answers arrive by polling, as skapi-js does without its realtime connection: a queued or streamed
/// request is dispatched, then polled until it settles. Streamed text is handed to an
/// `onStream(text, seq)` callback as it arrives. A poll survives failures on the way (no network, no
/// answer in time, 429, 5xx, no token): it waits longer each time, up to 30 seconds, and only the
/// server's own answer settles it (skapi-js 2.7.0). Cancel the calling Task to stop it.
extension Skapi {
    static let forwardMethods = ["get", "post", "delete", "put", "patch", "head"]
    static let upperMethods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]
    static let streamDegradedRetries = 3
    static let multipartLimit = 2 * 1024 * 1024 - 64 * 1024

    /// The full id skapi-js and the server know a forwarded request by.
    static func requestKey(_ method: String, _ url: String, _ service: String, _ requestId: String) -> String {
        "[\(method.uppercased())]\(url.lowercased())#\(service):\(requestId)"
    }

    private static func absoluteURL(_ v: String) throws {
        if v == "*" { return }
        guard let p = Check.splitURL(v), !p.scheme.isEmpty, !p.netloc.isEmpty else { throw paramError("\"\(v)\" is an invalid url.") }
    }

    private static func hasSecret(_ v: JSON?) -> Bool {
        switch v {
        case .some(.string(let s)): return s.contains("$CLIENT_SECRET")
        case .some(.object(let o)): return o.values.contains { hasSecret($0) }
        case .some(.array(let a)): return a.contains { hasSecret($0) }
        default: return false
        }
    }

    static func isStatusEnvelope(_ v: JSON) -> Bool {
        guard let o = v.object else { return false }
        return o["status"]?.isString == true && o["id"]?.isString == true && o.contains("in_queue")
    }

    private static func deliverChunks(_ result: JSON, _ cursorIn: Int, _ onStream: (String, Int) -> Void) -> (Int, Bool) {
        var cursor = cursorIn, moved = false
        if let chunks = result["chunks"]?.array {
            let sorted = chunks.filter { $0["seq"]?.int != nil }.sorted { $0["seq"]!.int! < $1["seq"]!.int! }
            for c in sorted {
                let seq = c["seq"]!.int!
                if seq > cursor {
                    cursor = seq
                    moved = true
                    if let t = c["txt"]?.string, !t.isEmpty { onStream(t, seq) }
                }
            }
        }
        if let last = result["last_seq"]?.int, last > cursor {
            cursor = last
            moved = true
        }
        return (cursor, moved)
    }

    private static func multipartBody(_ parts: [FormPart]) throws -> (Data, String) {
        let boundary = "----skapi" + UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        var out = Data()
        func textPart(_ name: String, _ value: String) {
            out += Data("--\(boundary)\r\nContent-Disposition: form-data; name=\"\(name)\"\r\n\r\n".utf8) + Data(value.utf8) + Data("\r\n".utf8)
        }
        func filePart(_ name: String, _ f: PreparedFile) {
            let safe = f.filename.replacingOccurrences(of: "\"", with: "%22").replacingOccurrences(of: "\r", with: "").replacingOccurrences(of: "\n", with: "")
            out += Data(("--\(boundary)\r\nContent-Disposition: form-data; name=\"\(name)\"; filename=\"\(safe)\"\r\n" +
                         "Content-Type: \(f.contentType ?? "application/octet-stream")\r\n\r\n").utf8) + f.content + Data("\r\n".utf8)
        }
        for p in parts {
            switch p {
            case .field(let name, let v):
                switch v {
                case .null: textPart(name, "")
                case .bool(let b): textPart(name, b ? "true" : "false")
                case .string(let s): textPart(name, s)
                default: textPart(name, v.jsonString)
                }
            case .file(let name, var f):
                f.name = name
                filePart(name, try prepareFiles([f])[0])
            case .data(let name, let d):
                filePart(name, PreparedFile(name: name, filename: name, content: d, contentType: nil))
            }
        }
        out += Data("--\(boundary)--\r\n".utf8)
        return (out, "multipart/form-data; boundary=\(boundary)")
    }

    /// Calls another API through Skapi. options: url (required), method, headers, data, params,
    /// secretName (a client secret stored on skapi.com; put "$CLIENT_SECRET" where it goes),
    /// skapiHeaders, queue, expires, stream, poll (milliseconds between checks), multipart, responseType,
    /// notify (status push for a queued request: see onRequestStatus), cref (your own reference for the
    /// request: 1 to 64 letters, digits, "_" or "-", stored on it and handed back by the reply and every
    /// read, so a send whose reply was lost can be found instead of sent again).
    ///
    /// form: an object merged into "data" (or "params" for GET, DELETE and HEAD).
    /// multipart: the form parts, with "multipart": true.
    /// Without queue/poll/stream: returns the API's answer. With poll or stream: waits for the answer
    /// and returns it, handing streamed text to onStream(text, seq). With a queue and no poll: returns
    /// ["id", "status", "queue_name", "in_queue", "request_id"] at once (plus "notify": true when status push
    /// was accepted, and "cref"); check it later with forwardRequestPoll.
    @discardableResult
    public func forwardRequest(_ options: JSON, form: JSON? = nil, multipart parts: [FormPart]? = nil,
                               onStream: (@Sendable (String, Int) -> Void)? = nil) async throws -> JSON {
        guard let options = options.object else { throw paramError("\"options\" is required.") }
        if (options["apiKeyHeader"] ?? .null) != .null || (options["apiKeyScheme"] ?? .null) != .null {
            throw paramError("\"apiKeyHeader\" and \"apiKeyScheme\" are no longer supported. Store the key as a client secret, name it with \"secretName\", and put \"$CLIENT_SECRET\" where the key goes.")
        }
        let multipart = options["multipart"]
        if let m = multipart, !m.isNull, !m.isBool { throw paramError("\"multipart\" should be type: <boolean>.") }
        let responseType = options["responseType"]?.string
        if let rt = options["responseType"], !rt.isNull {
            if rt == .string("response") {
                throw paramError("\"responseType\": \"response\" is not available here. The request is relayed from the server and what comes back is the stored answer, not a live Response; the destination's status code is the \"status_code\" of the row forwardRequestHistory lists.")
            }
            if !(rt == .string("json") || rt == .string("text")) { throw paramError("\"responseType\" should be either \"json\" or \"text\".") }
        }
        let method = options["method"].truthy ? options["method"]! : "POST"
        let mergeInto = ["get", "delete", "head"].contains(method.string?.lowercased() ?? "") ? "params" : "data"
        var params: JSONObject = ["url": options["url"] ?? .null, "method": method]
        for k in ["secretName", "headers", "data", "params", "skapiHeaders", "service", "owner", "queue", "expires", "stream", "realtime",
                  "notify", "poll", "cref"] {
            if let v = options[k], !v.isNull { params[k] = v }
        }
        if parts != nil && multipart?.bool != true { throw paramError("Form parts in \"multipart\" need \"multipart\": true in the options.") }
        if multipart?.bool == true {
            if let d = options["data"], !d.isNull { throw paramError("\"data\" cannot be sent with \"multipart\": true. The form itself is the body.") }
            guard let parts = parts else { throw paramError("\"multipart\": true needs the form parts in \"multipart\".") }
            let (body, contentType) = try Skapi.multipartBody(parts)
            let b64 = body.base64EncodedString()
            if b64.utf8.count > Skapi.multipartLimit {
                throw paramError("Multipart body is too large: \(b64.utf8.count) bytes once base64 encoded, and the limit is \(Skapi.multipartLimit). Upload the file first and send its url instead.")
            }
            params["body_b64"] = .string(b64)
            params["body_content_type"] = .string(contentType)
        } else if let f = form?.object, !f.isEmpty {
            if let existing = params[mergeInto], !existing.isNull, !existing.isObject { throw paramError("\"\(mergeInto)\" should be type: <object>.") }
            if JSON.object(f).asciiJSONString.utf8.count > 2 * 1024 * 1024 { throw SkapiError("Data should not exceed 2MB", code: "INVALID_REQUEST") }
            var merged = f
            for (k, v) in params[mergeInto]?.object ?? JSONObject() { merged[k] = v }
            params[mergeInto] = .object(merged)
        }
        return try await dispatchForward(params, onStream: onStream, responseType: responseType)
    }

    /// The shortest polling interval accepted, in milliseconds (skapi-js 2.4.4). A shorter one is refused
    /// with INVALID_PARAMETER, never raised quietly: forwardRequest's "poll" (0 still means "do not poll"),
    /// forwardRequestPoll's `poll` and forwardRequestStream's "poll".
    public static let minPollIntervalMs: Double = 1000

    static func assertPollInterval(_ value: Double, _ name: String = "poll") throws {
        if !value.isFinite || value < minPollIntervalMs {
            throw paramError("\"\(name)\" should be a number of milliseconds, \(Int(minPollIntervalMs)) or more.")
        }
    }

    private func dispatchForward(_ paramsIn: JSONObject, onStream: (@Sendable (String, Int) -> Void)?, responseType: String?) async throws -> JSON {
        var params = paramsIn
        let secretNamed = params["secretName"].truthy
        let poll = params.removeValue(forKey: "poll")
        // 0 (or false, or absent) means "do not poll"; any other number is the interval.
        if let n = poll?.number, n != 0 { try Skapi.assertPollInterval(n) }
        let latency: Double = poll?.number ?? ((poll?.truthy ?? false) ? 1000 : 0)
        try await ensureConnection()
        let signedIn = await self.signedIn()
        if (latency > 0 || params["stream"].truthy) && !params["queue"].truthy {
            params["queue"] = .string("\(me.isEmpty ? "anonymous" : me)-" + DB.randomKey(6))
        }
        var body = JSONObject()
        guard let url = params["url"]?.string, !url.isEmpty else { throw paramError("\"url\" should be type: <string>.") }
        try Skapi.absoluteURL(url)
        body["url"] = .string(url)
        var hasSecret = url.contains("$CLIENT_SECRET")
        if let sn = params["secretName"] {
            guard sn.isString else { throw paramError("\(jd(sn)) is invalid in \"secretName\". allowed type or value is: Type<string>.") }
            body["secretName"] = sn
        }
        let m = params["method"]
        if let mm = m, mm.truthy, !(mm.string.map { Skapi.forwardMethods.contains($0.lowercased()) } ?? false) {
            throw paramError("\"method\" should be one of \"GET\", \"POST\", \"PUT\", \"PATCH\", \"DELETE\" or \"HEAD\".")
        }
        let methodLower = (m?.string ?? "post").lowercased()
        body["method"] = .string(methodLower)
        for k in ["stream", "realtime", "notify"] {
            if let v = params[k] {
                guard v.isBool else { throw paramError("\"\(k)\" should be type: <boolean>.") }
                body[k] = v
            }
        }
        if let c = params["cref"] { body["cref"] = .string(try Skapi.clientReference(c)) }
        if let h = params["headers"] {
            if h.truthy && !h.isObject { throw paramError("\"headers\" should be type: <object>.") }
            for k in h.object?.keys ?? [] where k.lowercased().hasPrefix("x-skapi-") {
                throw paramError("\"headers\" cannot set \"\(k)\": the \"x-skapi-\" prefix is reserved. Use \"skapiHeaders\" to tell the destination who the caller is.")
            }
            hasSecret = hasSecret || Skapi.hasSecret(h)
            body["headers"] = h
        }
        if let sh = params["skapiHeaders"] {
            if sh.isBool { body["skapiHeaders"] = sh }
            else if let o = sh.object { body["skapiHeaders"] = ["user": .bool(o["user"].truthy), "service": .bool(o["service"].truthy)] }
            else { throw paramError("\"skapiHeaders\" should be type: <boolean> or { user?: boolean; service?: boolean }.") }
        }
        for k in ["data", "params"] {
            if let v = params[k] {
                if v.truthy && !v.isObject { throw paramError("\"\(k)\" should be type: <object>.") }
                hasSecret = hasSecret || Skapi.hasSecret(v)
                body[k] = v
            }
        }
        for k in ["body_b64", "body_content_type"] where params.contains(k) { body[k] = params[k] }
        if let e = params["expires"] {
            guard e.isNumber else { throw paramError("\(jd(e)) is invalid in \"expires\". allowed type or value is: Type<number>.") }
            body["expires"] = e
        }
        if let q = params["queue"] {
            guard q.isString else { throw paramError("\(jd(q)) is invalid in \"queue\". allowed type or value is: Type<string>.") }
            body["queue"] = q
        }
        for k in ["service", "owner"] where params.contains(k) { body[k] = params[k] }
        if body["realtime"].truthy && !body["stream"].truthy { throw paramError("\"realtime\" requires \"stream\": true.") }
        if body["body_b64"].truthy && body["data"].truthy { throw paramError("\"data\" cannot be sent with \"multipart\": true.") }
        if secretNamed && !hasSecret { body["secretName"] = nil }

        let token = signedIn ? try await tokenForRequest() : nil
        let extra = signedIn ? ["X-Access-Token": sess?.accessToken.jwtToken ?? ""] : nil
        var res = try await requester.request("csr", .object(body), auth: signedIn, token: token, extraHeaders: extra)

        let svc = params["service"]?.string ?? service
        if Skapi.isStatusEnvelope(res), let st = res["status"]?.string, st == "running" || st == "pending" {
            let fullId = Skapi.requestKey(methodLower, url, svc, res["id"]?.string ?? "")
            res["request_id"] = .string(fullId)
            // The server accepted `notify` (an older one ignores it and says nothing).
            let notified = res["notify"] == .bool(true)
            if notified { statusPush.noteAck() }
            // The server echoes `cref`; kept here too so the reply always carries it.
            if let c = body["cref"], res["cref"] == nil { res["cref"] = c }
            if latency > 0 || body["stream"].truthy {
                res = try await pollRequest(fullId, wait: latency > 0 ? latency : 1000, onStream: onStream,
                                            service: params["service"]?.string, owner: params["owner"]?.string, notify: notified)
            }
        }
        return Skapi.responseType(res, responseType)
    }

    /// Checks a client reference (`cref`): 1 to 64 letters, digits, "_" or "-", the rule the server
    /// stores it under. Refused here so a bad one fails before anything is sent.
    static func clientReference(_ v: JSON) throws -> String {
        guard let s = v.string, (1...64).contains(s.utf8.count),
              s.unicodeScalars.allSatisfy({ ($0.isASCII && CharacterSet.alphanumerics.contains($0)) || $0 == "_" || $0 == "-" }) else {
            throw paramError("\"cref\" should be 1 to 64 characters of letters, digits, \"_\" or \"-\".")
        }
        return s
    }

    private static func responseType(_ res: JSON, _ responseType: String?) -> JSON {
        guard let rt = responseType, !rt.isEmpty, !isStatusEnvelope(res), res["status"] != .string("stopped") else { return res }
        if rt == "text" { return res.isString ? res : .string(res.jsonString) }
        if let s = res.string { return (try? JSON.parse(s)) ?? res }
        return res
    }

    private func requestId(_ requestId: String, url: String?, method: String?, service: String?) throws -> String {
        if requestId.isEmpty { throw paramError("\"requestId\" should be type: <string>.") }
        if requestId.contains("#") { return requestId }
        guard let u = url, let m = method, !u.isEmpty, !m.isEmpty else {
            throw paramError("\"url\" and \"method\" are required to address a request by its short id.")
        }
        try Skapi.absoluteURL(u)
        return Skapi.requestKey(m, u, service ?? self.service, requestId)
    }

    /// Waits for a queued request (its request_id, or its short id with url and method) and returns the answer.
    /// poll: milliseconds between checks, 1000 or more (0 means the default, 1000).
    /// notify: the request was dispatched with `notify` and the reply said "notify": true. While status
    /// frames arrive the poll then reads the request only when a frame names it, plus a heartbeat every
    /// minute. Without frames it runs at `poll` as always.
    ///
    /// Failures on the way (NETWORK_ERROR, TIMEOUT, RATE_LIMITED, TOO_MANY_REQUESTS, SERVER_ERROR, no
    /// token) never end the poll: it tries again, waiting twice as long each time up to 30 seconds. A 401
    /// refreshes the token once per run of them. While signed out it waits for a sign in, sending
    /// nothing. Only the server's own answer settles it. Cancel the calling Task to stop it.
    public func forwardRequestPoll(_ requestId: String, poll: Double = 1000, url: String? = nil, method: String? = nil,
                                   onStream: (@Sendable (String, Int) -> Void)? = nil, service: String? = nil, owner: String? = nil,
                                   notify: Bool = false) async throws -> JSON {
        let wait = poll == 0 ? 1000 : poll
        try Skapi.assertPollInterval(wait)
        let fullId = try self.requestId(requestId, url: url, method: method, service: service)
        return try await pollRequest(fullId, wait: wait, onStream: onStream, service: service, owner: owner, notify: notify)
    }

    func pollRequest(_ fullId: String, wait: Double, onStream: (@Sendable (String, Int) -> Void)?, service: String?, owner: String?,
                     notify: Bool) async throws -> JSON {
        try await ensureConnection()
        // Fixed for the poll's life: a signed-in poll that finds itself signed out waits for a sign in.
        let auth = await signedIn()
        let signal = WakeSignal()
        var unhold: (@Sendable () -> Void)?
        var unwake: (@Sendable () -> Void)?
        if notify {
            // Held, and frames naming this request listened to, for the poll's whole life.
            unhold = statusPush.hold(self)
            unwake = statusPush.addWaker(fullId) { signal.wake() }
        }
        defer {
            unwake?()
            unhold?()
        }
        var cursor = 0, stalled = 0, failures = 0
        var refreshTried = false
        var lastPollAt: Double?
        var nextWait = wait
        while true {
            let woken = try await signal.sleep(ms: nextWait)
            nextWait = wait
            // Status frames are arriving: read when one names this request, otherwise only as a heartbeat.
            if notify && !woken && statusPush.warm, let at = lastPollAt, monoMs() - at < StatusPush.idlePollMs { continue }
            // Signed out: nothing to read with, and asking for a token on every check would sign out again.
            if auth, !(await signedIn()) { continue }
            while true {
                var body: JSONObject = ["id": .string(fullId), "service": .string(service ?? self.service), "owner": .string(owner ?? self.owner)]
                if onStream != nil { body["since"] = .number(Double(cursor)) }
                lastPollAt = monoMs()
                let result: JSON
                do {
                    result = try await call("csr-poll", .object(body), auth: auth)
                } catch {
                    if Task.isCancelled { throw CancellationError() }
                    if isUnauthorized(error) {
                        // The gateway refused the token: refresh it once (time limited), then carry on.
                        failures += 1
                        if !refreshTried {
                            refreshTried = true
                            try? await refreshSession()
                        }
                        nextWait = max(wait, pollRetryDelay(wait, failures))
                        break
                    }
                    if isTransportFailure(error) {
                        failures += 1
                        nextWait = max(wait, pollRetryDelay(wait, failures))
                        break
                    }
                    throw error  // the server's own answer (NOT_EXISTS included) ends the poll
                }
                failures = 0
                refreshTried = false
                // chunks, "more" and a running status belong to skapi's status envelope; a resolved read is
                // the destination's own body, returned as it is
                let envelope = Skapi.isStatusEnvelope(result)
                var moved = false
                if let cb = onStream, envelope { (cursor, moved) = Skapi.deliverChunks(result, cursor, cb) }
                let running = envelope && (result["status"] == .string("running") || result["status"] == .string("pending"))
                let more = envelope && result["more"].truthy
                if more && moved { stalled = 0; continue }
                if running { stalled = 0; break }
                stalled = more ? stalled + 1 : 0
                if more && stalled < Skapi.streamDegradedRetries {
                    signal.clear()  // a degraded read waits out the interval: re-asking a failing table at once does not help
                    break
                }
                return result
            }
        }
    }

    /// Reads a streamed request's text from `since` (or the start) until it settles; returns the final answer.
    /// options: ["poll"?, "since"?, "url"?, "method"?, "service"?, "owner"?]. Failures on the way never end
    /// the read, as for forwardRequestPoll.
    public func forwardRequestStream(_ requestId: String, options: JSON? = nil, onStream: (@Sendable (String, Int) -> Void)? = nil) async throws -> JSON {
        let o = options?.object ?? JSONObject()
        let latency = o["poll"]?.number ?? 1000
        try Skapi.assertPollInterval(latency)
        if let s = o["since"], !s.isNumber { throw paramError("\"since\" should be a number.") }
        let fullId = try self.requestId(requestId, url: o["url"]?.string, method: o["method"]?.string, service: o["service"]?.string)
        try await ensureConnection()
        let auth = await signedIn()
        var cursor = max(0, Int(o["since"]?.number ?? 0))
        var stalled = 0, failures = 0
        var refreshTried = false
        while true {
            if auth, !(await signedIn()) {
                // Signed out: wait for a sign in instead of signing out again each read.
                try await Task.sleep(nanoseconds: UInt64(latency * 1_000_000))
                continue
            }
            let result: JSON
            do {
                result = try await call("csr-poll", ["id": .string(fullId), "service": .string(o["service"]?.string ?? service),
                                                     "owner": .string(o["owner"]?.string ?? owner), "since": .number(Double(cursor))],
                                        auth: auth)
            } catch {
                // The same rules as forwardRequestPoll (skapi-js 2.7.0).
                if Task.isCancelled { throw CancellationError() }
                let unauthorized = isUnauthorized(error)
                if !unauthorized && !isTransportFailure(error) { throw error }
                failures += 1
                if unauthorized && !refreshTried {
                    refreshTried = true
                    try? await refreshSession()
                }
                try await Task.sleep(nanoseconds: UInt64(max(latency, pollRetryDelay(latency, failures)) * 1_000_000))
                continue
            }
            failures = 0
            refreshTried = false
            if !Skapi.isStatusEnvelope(result) { return result }
            var moved = false
            if let cb = onStream { (cursor, moved) = Skapi.deliverChunks(result, cursor, cb) }
            else if let last = result["last_seq"]?.int, last > cursor { cursor = last; moved = true }
            let running = result["status"] == .string("running") || result["status"] == .string("pending")
            let more = result["more"].truthy
            if more && moved { continue }
            stalled = more ? stalled + 1 : 0
            if !running && (!more || stalled >= Skapi.streamDegradedRetries) { return result }
            try await Task.sleep(nanoseconds: UInt64(latency * 1_000_000))
        }
    }

    /// Stores `data` as a streamed request's final answer, so later polls return it.
    /// options: ["url"?, "method"?, "service"?, "owner"?, "ifAbsent"?]. With "ifAbsent": true the answer is
    /// stored only when the request has no stored result yet; otherwise nothing changes and the answer is
    /// ["finalized": false, "reason": "exists"], so two devices settling the same turn cannot replace a
    /// complete answer with a partial one.
    @discardableResult
    public func forwardRequestFinalize(_ requestId: String, data: JSON? = nil, options: JSON? = nil) async throws -> JSON {
        let o = options?.object ?? JSONObject()
        if let ia = o["ifAbsent"], !ia.isNull, !ia.isBool { throw paramError("\"ifAbsent\" should be type: <boolean>.") }
        let fullId = try self.requestId(requestId, url: o["url"]?.string, method: o["method"]?.string, service: o["service"]?.string)
        try await ensureConnection()
        var body: JSONObject = ["id": .string(fullId)]
        if let d = data, !d.isNull { body["data"] = d }
        body["service"] = .string(o["service"]?.string ?? service)
        body["owner"] = .string(o["owner"]?.string ?? owner)
        // Sent only when asked, so a call without it is the same request as before.
        if o["ifAbsent"]?.bool == true { body["if_absent"] = true }
        return try await call("csr-finalize", .object(body), auth: await signedIn())
    }

    /// The forwarded requests you made to one url and method, with their answers.
    /// params: ["url", "method", "status"?, "queue"?, "queue_exclude"?, "queue_exact"?, "compact"?, "fields"?,
    /// "after"?, "deadline"?, "fresh"?].
    ///
    /// "queue" alone is a prefix range ("u1" also matches "u1-bg"); "queue_exact": true reads only that
    /// queue's rows. Requests queued before 2026-06-05 are stored under an older queue format and are not
    /// listed with "queue_exact"; list them without it. "queue_exclude" drops one queue's rows after the
    /// read, so a page can come back short while more rows remain: keep paging by startKey/endOfList.
    /// "fields": "ids" is a light listing (each row only its id, status, times, queue and cref, no bodies);
    /// "after" lists only requests newer than that request id ("stamp:entropy"); "deadline" bounds the
    /// call in milliseconds (then TIMEOUT).
    public func forwardRequestHistory(_ params: JSON, fetchOptions: FetchOptions? = nil) async throws -> JSON {
        let p = params.object ?? JSONObject()
        let deadline = try readTransportOptions(p)
        try await ensureConnection()
        let svc = p["service"]?.string ?? service
        let own = p["owner"]?.string ?? owner
        for key in ["url", "method"] where !p.contains(key) { throw paramError("Key \"\(key)\" is required.") }
        guard let url = p["url"]?.string else { throw paramError("\(jd(p["url"])) is invalid in \"url\". allowed type or value is: Type<string>.") }
        guard let method = p["method"]?.string, Skapi.upperMethods.contains(method) else {
            throw paramError("\(jd(p["method"])) is invalid in \"method\". allowed types or values are: " + Skapi.upperMethods.map { jd(.string($0)) }.joined(separator: ", ") + ".")
        }
        if let s = p["status"], !(s.string.map { ["pending", "running", "resolved", "failed"].contains($0) } ?? false) {
            throw paramError("\(jd(s)) is invalid in \"status\". allowed types or values are: \"pending\", \"running\", \"resolved\", \"failed\".")
        }
        for k in ["queue", "queue_exclude"] {
            if let v = p[k], !v.isNull, !v.isString { throw paramError("\(jd(v)) is invalid in \"\(k)\". allowed type or value is: Type<string>.") }
        }
        for k in ["compact", "queue_exact"] {
            if let v = p[k], !v.isBool { throw paramError("\(jd(v)) is invalid in \"\(k)\". allowed type or value is: Type<boolean>.") }
        }
        if let f = p["fields"], !f.isNull, f != .string("ids") { throw paramError("\"fields\" should be \"ids\".") }
        if let a = p["after"], !a.isNull, !a.isString { throw paramError("\(jd(a)) is invalid in \"after\". allowed type or value is: Type<string>.") }
        let prefix = Skapi.requestKey(method, url, svc, "")
        var req: JSONObject = ["id": .string(prefix)]
        if p["queue"].truthy { req["queue"] = p["queue"] }
        if p["status"].truthy { req["status"] = p["status"] }
        req["service"] = .string(svc)
        req["owner"] = .string(own)
        if p["compact"].truthy { req["compact"] = true }
        if p["queue_exact"].truthy { req["queue_exact"] = true }
        if p["queue_exclude"].truthy { req["queue_exclude"] = p["queue_exclude"] }
        if p["fields"].truthy { req["fields"] = p["fields"] }
        if p["after"].truthy { req["after"] = p["after"] }
        if req["queue"].truthy { req["id_prefix"] = req.removeValue(forKey: "id") }
        let auth = await signedIn()
        let request = req, fo = fetchOptions?.object
        var res = try await withDeadline(deadline) { try await self.call("csr-poll", .object(request), auth: auth, fetchOptions: fo) }
        if let list = res["list"]?.array {
            res["list"] = .array(list.map { r in
                let rslv = r["rslv"]?.object
                var item: JSONObject = ["id": r["id"] ?? .null, "status_code": rslv?["status_code"] ?? .null,
                                        "response_body": rslv.map { ($0["body"].truthy ? $0["body"] : $0["truncated"]) ?? .null } ?? .null]
                // A "fields": "ids" row already names created, updated and status in full.
                for (key, src) in [("error", "err"), ("created", "stmp"), ("updated", "utmp")] { if let v = r[src] ?? r[key] { item[key] = v } }
                if let att = r["att"]?.number { item["executed"] = .number(att * 1000) }
                if let rt = r["rtmp"], rt.isNumber { item["responded"] = rt }
                for (key, src) in [("request_body", "reqbdy"), ("expires", "expt"), ("queue_name", "qid"), ("cref", "cref"),
                                   ("request_text", "reqtxt"), ("response_text", "rslvtxt")] { if let v = r[src] { item[key] = v } }
                if let v = r["stts"] ?? r["status"] { item["status"] = v }
                if let mk = r["rslvmk"], !mk.isNull { item["response_complete_marker"] = .bool(mk.truthy) }
                if r["cmpct"].truthy { item["compact"] = true }
                item["request_id"] = .string(prefix + (r["id"]?.pyString ?? "None"))
                return .object(item)
            })
        }
        return res
    }

    /// Cancels a queued request that has not run yet: ["url", "method", "id"].
    @discardableResult
    public func cancelForwardRequest(_ params: JSON) async throws -> JSON {
        let p = params.object ?? JSONObject()
        for key in ["url", "method", "id"] where !p.contains(key) { throw paramError("Key \"\(key)\" is required.") }
        guard let method = p["method"]?.string, Skapi.upperMethods.contains(method) else {
            throw paramError("\(jd(p["method"])) is invalid in \"method\". allowed types or values are: " + Skapi.upperMethods.map { jd(.string($0)) }.joined(separator: ", ") + ".")
        }
        for key in ["url", "id", "queue"] {
            if let v = p[key], !v.isString { throw paramError("\(jd(v)) is invalid in \"\(key)\". allowed type or value is: Type<string>.") }
        }
        try await ensureConnection()
        let svc = p["service"]?.string ?? service
        let fullId = Skapi.requestKey(method, p["url"]!.string!, svc, p["id"]!.string!)
        return try await call("csr-cancel", ["id": .string(fullId), "service": .string(svc), "owner": .string(p["owner"]?.string ?? owner)],
                              auth: await signedIn())
    }

    /// How many requests are waiting in one of your queues. Signed-in users only.
    public func forwardRequestQueueCount(_ params: JSON) async throws -> JSON {
        let p = params.object ?? JSONObject()
        guard let q = p["queue"]?.string, !q.isEmpty else { throw paramError("\"queue\" is required.") }
        var res = try await call("csr-poll", ["service": .string(p["service"]?.string ?? service), "owner": .string(p["owner"]?.string ?? owner),
                                              "queue": .string(q + ":")], auth: true)
        if var name = res["queue_name"]?.string {
            while name.hasSuffix(":") { name.removeLast() }
            res["queue_name"] = .string(name)
        }
        return res
    }

    /// How many requests forwardRequestStatus asks about per call to the server.
    static let statusBatchMax = 100

    /// Reads where many forwarded requests stand, in one call per 100 (skapi-js 2.7.0): status ("pending",
    /// "running", "resolved", "failed", "cancelled", or "missing" for one this caller cannot see), stream
    /// position ("last_seq", "final_seq"), whether a result is stored ("has_body"), timestamps and "cref".
    /// No bodies. A strongly consistent read, so a request that just changed shows its new status.
    ///
    /// Made for showing many unfinished requests correctly after the app was away: one call says what
    /// happened to all of them.
    ///
    /// requests: full request ids (.string), or ["id", "url", "method"] with the short id.
    /// options: ["service"?, "owner"?, "deadline"? (milliseconds per call, then TIMEOUT), "fresh"?].
    /// Returns ["list": [...]] in the order asked.
    public func forwardRequestStatus(_ requests: [JSON], options: JSON? = nil) async throws -> JSON {
        let o = options?.object ?? JSONObject()
        let deadline = try readTransportOptions(o)
        let svc = o["service"]?.string ?? service
        let own = o["owner"]?.string ?? owner
        let ids: [String] = try requests.map { r in
            if let s = r.string { return try self.requestId(s, url: nil, method: nil, service: svc) }
            guard let ro = r.object, let id = ro["id"]?.string else {
                throw paramError("\"requests\" should be an array of request ids or { id, url, method }.")
            }
            return try self.requestId(id, url: ro["url"]?.string, method: ro["method"]?.string, service: svc)
        }
        try await ensureConnection()
        let auth = await signedIn()
        var out: JSONObject = ["list": .array([])]
        var list: [JSON] = []
        var i = 0
        while i < ids.count {
            let batch = Array(ids[i..<min(ids.count, i + Skapi.statusBatchMax)])
            let res = try await withDeadline(deadline) {
                try await self.call("csr-poll", ["ids": .array(batch.map { .string($0) }), "service": .string(svc), "owner": .string(own)], auth: auth)
            }
            // Anything else the server reports beside the list (queue counters) is kept.
            for (k, v) in res.object ?? [:] where k != "list" && out[k] == nil { out[k] = v }
            list += res["list"]?.array ?? []
            i += Skapi.statusBatchMax
        }
        out["list"] = .array(list)
        return .object(out)
    }

    /// The counters of up to 20 queues: ["queues": [name: ["cnt", "rct", "seq", "in_queue"]]]. "rct" grows
    /// when a request on the queue finishes and "seq" when one is added: read these on every tick and the
    /// requests themselves (forwardRequestStatus) only when one moved. A queue that never had a request is
    /// left out. options: ["service"?, "owner"?, "deadline"?, "fresh"?].
    public func forwardRequestQueueCounters(_ queues: [String], options: JSON? = nil) async throws -> JSON {
        if queues.isEmpty || queues.count > 20 || queues.contains(where: { $0.isEmpty || $0.contains(":") }) {
            throw paramError("\"queues\" should be an array of 1 to 20 queue names.")
        }
        let o = options?.object ?? JSONObject()
        let deadline = try readTransportOptions(o)
        try await ensureConnection()
        let auth = await signedIn()
        let body: JSON = ["queues": .array(queues.map { .string($0) }), "service": .string(o["service"]?.string ?? service),
                          "owner": .string(o["owner"]?.string ?? owner)]
        let res = try await withDeadline(deadline) { try await self.call("csr-poll", body, auth: auth) }
        if let q = res["queues"], q.isObject { return ["queues": q] }
        return ["queues": .object(JSONObject())]
    }

    /// Reads one forwarded request in full, always in the same shape: ["id", "status", "body"?, "error"?,
    /// "chunks"?, "last_seq"?, "final_seq"?, "more"?, "body_unavailable"?, "created"?, "updated"?,
    /// "executed"?, "responded"?, "cref"?], whatever state it is in. Unlike a poll, a resolved request does
    /// not come back as its bare body, so the status is always there to read, and a failed streamed request
    /// comes back with the text that arrived before it failed.
    ///
    /// params: ["id" (with "url" and "method", or a full id alone), "since"? (a chunk sequence, 0 for the
    /// beginning: the streamed text after it comes back too, with "more": true when there is more than
    /// one read returns), "service"?, "owner"?, "deadline"?, "fresh"?]. A stored result that cannot be
    /// loaded right now comes back as "body_unavailable": true instead of failing the read.
    public func forwardRequestRead(_ params: JSON) async throws -> JSON {
        guard let p = params.object else { throw paramError("\"params\" should be type: <object>.") }
        if let s = p["since"], !s.isNull, !(s.number?.isFinite ?? false) { throw paramError("\"since\" should be a number.") }
        let deadline = try readTransportOptions(p)
        let svc = p["service"]?.string ?? service
        guard let id = p["id"]?.string else { throw paramError("\"requestId\" should be type: <string>.") }
        let fullId = try requestId(id, url: p["url"]?.string, method: p["method"]?.string, service: svc)
        try await ensureConnection()
        let auth = await signedIn()
        var body: JSONObject = ["id": .string(fullId), "envelope": true, "service": .string(svc), "owner": .string(p["owner"]?.string ?? owner)]
        if let since = p["since"]?.number { body["since"] = .number(max(0, since)) }
        let request = body
        return try await withDeadline(deadline) { try await self.call("csr-poll", .object(request), auth: auth) }
    }

    // ---- inquiry ----------------------------------------------------------------------------------

    /// Sends a message to the project's owner: ["name", "email", "subject", "message"].
    @discardableResult
    public func sendInquiry(_ data: JSON) async throws -> String {
        try await ensureConnection()
        let d = data.object ?? JSONObject()
        for key in ["name", "email", "subject", "message"] where !d.contains(key) { throw paramError("Key \"\(key)\" is required.") }
        for key in ["name", "subject", "message"] where !d[key]!.isString {
            throw paramError("\(jd(d[key])) is invalid in \"\(key)\". allowed type or value is: Type<string>.")
        }
        _ = try Check.email(d["email"])
        _ = try await call("send-inquiry", ["name": d["name"]!, "email": d["email"]!, "subject": d["subject"]!, "message": d["message"]!])
        return "SUCCESS: Inquiry has been sent."
    }
}
