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
/// `onStream(text, seq)` callback as it arrives.
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
    /// skapiHeaders, queue, expires, stream, poll (milliseconds between checks), multipart, responseType.
    ///
    /// form: an object merged into "data" (or "params" for GET, DELETE and HEAD).
    /// multipart: the form parts, with "multipart": true.
    /// Without queue/poll/stream: returns the API's answer. With poll or stream: waits for the answer
    /// and returns it, handing streamed text to onStream(text, seq). With a queue and no poll: returns
    /// ["id", "status", "queue_name", "in_queue", "request_id"] at once; check it later with forwardRequestPoll.
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
        for k in ["secretName", "headers", "data", "params", "skapiHeaders", "service", "owner", "queue", "expires", "stream", "realtime", "poll"] {
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
        for k in ["stream", "realtime"] {
            if let v = params[k] {
                guard v.isBool else { throw paramError("\"\(k)\" should be type: <boolean>.") }
                body[k] = v
            }
        }
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

        let token = signedIn ? try await freshIdToken() : nil
        let extra = signedIn ? ["X-Access-Token": sess?.accessToken.jwtToken ?? ""] : nil
        var res = try await requester.request("csr", .object(body), auth: signedIn, token: token, extraHeaders: extra)

        let svc = params["service"]?.string ?? service
        if Skapi.isStatusEnvelope(res), let st = res["status"]?.string, st == "running" || st == "pending" {
            let fullId = Skapi.requestKey(methodLower, url, svc, res["id"]?.string ?? "")
            res["request_id"] = .string(fullId)
            if latency > 0 || body["stream"].truthy {
                res = try await forwardRequestPoll(fullId, poll: latency > 0 ? latency : 1000, onStream: onStream,
                                                   service: params["service"]?.string, owner: params["owner"]?.string)
            }
        }
        return Skapi.responseType(res, responseType)
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
    public func forwardRequestPoll(_ requestId: String, poll: Double = 1000, url: String? = nil, method: String? = nil,
                                   onStream: (@Sendable (String, Int) -> Void)? = nil, service: String? = nil, owner: String? = nil) async throws -> JSON {
        let wait = poll == 0 ? 1000 : poll
        try Skapi.assertPollInterval(wait)
        let fullId = try self.requestId(requestId, url: url, method: method, service: service)
        try await ensureConnection()
        var cursor = 0, stalled = 0
        while true {
            try await Task.sleep(nanoseconds: UInt64(wait * 1_000_000))
            while true {
                var body: JSONObject = ["id": .string(fullId), "service": .string(service ?? self.service), "owner": .string(owner ?? self.owner)]
                if onStream != nil { body["since"] = .number(Double(cursor)) }
                let result = try await call("csr-poll", .object(body), auth: await signedIn())
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
                if more && stalled < Skapi.streamDegradedRetries { break }
                return result
            }
        }
    }

    /// Reads a streamed request's text from `since` (or the start) until it settles; returns the final answer.
    /// options: ["poll"?, "since"?, "url"?, "method"?, "service"?, "owner"?].
    public func forwardRequestStream(_ requestId: String, options: JSON? = nil, onStream: (@Sendable (String, Int) -> Void)? = nil) async throws -> JSON {
        let o = options?.object ?? JSONObject()
        let latency = o["poll"]?.number ?? 1000
        try Skapi.assertPollInterval(latency)
        if let s = o["since"], !s.isNumber { throw paramError("\"since\" should be a number.") }
        let fullId = try self.requestId(requestId, url: o["url"]?.string, method: o["method"]?.string, service: o["service"]?.string)
        try await ensureConnection()
        var cursor = max(0, Int(o["since"]?.number ?? 0))
        var stalled = 0
        while true {
            let result = try await call("csr-poll", ["id": .string(fullId), "service": .string(o["service"]?.string ?? service),
                                                     "owner": .string(o["owner"]?.string ?? owner), "since": .number(Double(cursor))],
                                        auth: await signedIn())
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
    @discardableResult
    public func forwardRequestFinalize(_ requestId: String, data: JSON? = nil, options: JSON? = nil) async throws -> JSON {
        let o = options?.object ?? JSONObject()
        let fullId = try self.requestId(requestId, url: o["url"]?.string, method: o["method"]?.string, service: o["service"]?.string)
        try await ensureConnection()
        var body: JSONObject = ["id": .string(fullId)]
        if let d = data, !d.isNull { body["data"] = d }
        body["service"] = .string(o["service"]?.string ?? service)
        body["owner"] = .string(o["owner"]?.string ?? owner)
        return try await call("csr-finalize", .object(body), auth: await signedIn())
    }

    /// The forwarded requests you made to one url and method, with their answers.
    /// params: ["url", "method", "status"?, "queue"?, "queue_exclude"?, "queue_exact"?, "compact"?].
    public func forwardRequestHistory(_ params: JSON, fetchOptions: FetchOptions? = nil) async throws -> JSON {
        try await ensureConnection()
        let p = params.object ?? JSONObject()
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
        let prefix = Skapi.requestKey(method, url, svc, "")
        var req: JSONObject = ["id": .string(prefix)]
        if p["queue"].truthy { req["queue"] = p["queue"] }
        if p["status"].truthy { req["status"] = p["status"] }
        req["service"] = .string(svc)
        req["owner"] = .string(own)
        if p["compact"].truthy { req["compact"] = true }
        if p["queue_exact"].truthy { req["queue_exact"] = true }
        if p["queue_exclude"].truthy { req["queue_exclude"] = p["queue_exclude"] }
        if req["queue"].truthy { req["id_prefix"] = req.removeValue(forKey: "id") }
        var res = try await call("csr-poll", .object(req), auth: await signedIn(), fetchOptions: fetchOptions?.object)
        if let list = res["list"]?.array {
            res["list"] = .array(list.map { r in
                let rslv = r["rslv"]?.object
                var item: JSONObject = ["id": r["id"] ?? .null, "status_code": rslv?["status_code"] ?? .null,
                                        "response_body": rslv.map { ($0["body"].truthy ? $0["body"] : $0["truncated"]) ?? .null } ?? .null]
                for (key, src) in [("error", "err"), ("created", "stmp"), ("updated", "utmp")] { if let v = r[src] { item[key] = v } }
                if let att = r["att"]?.number { item["executed"] = .number(att * 1000) }
                if let rt = r["rtmp"], rt.isNumber { item["responded"] = rt }
                for (key, src) in [("request_body", "reqbdy"), ("expires", "expt"), ("status", "stts"), ("queue_name", "qid"),
                                   ("request_text", "reqtxt"), ("response_text", "rslvtxt")] { if let v = r[src] { item[key] = v } }
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
