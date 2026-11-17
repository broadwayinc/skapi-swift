import Foundation

/// User-side newsletters, subscriptions between users, the feed, and ticket listings, ported from
/// skapi-py (_social.py) and skapi-js (src/methods/subscription.ts, src/methods/user.ts).

let ticketKeys: [String: String] = [
    "tkid": "ticket_id", "cond": "condition", "stmp": "timestamp", "upd": "updated", "acts": "actions", "actn": "action",
    "cnt": "count", "ttl": "time_to_live", "plch": "placeholder", "hash": "hash", "desc": "description", "pmc": "limit_per_user",
    "fail": "failed", "rv": "rules_version", "on": "enabled", "qn": "queued", "qdue": "queued_due", "cc": "concurrency",
    "cf": "when_full", "cn": "running", "ln": "waiting", "sc": "self_calling",
]

/// A ticket row as skapi-js returns it (short server keys renamed, consume ids split).
func mapTicket(_ t: JSONObject) -> JSONObject {
    var out = JSONObject()
    for (k, v) in t {
        if k == "tkid", let s = v.string {
            let parts = s.components(separatedBy: "#")
            if parts.count == 1 {
                out["ticket_id"] = .string(parts[0])
            } else {
                out["ticket_id"] = .string(parts[1])
                let consumeId = parts.count > 2 ? parts[2] : ""
                out["consume_id"] = .string(consumeId)
                out["user_id"] = .string(parts.count > 3 ? parts[3...].joined(separator: "#") : "")
                out["is_test"] = .bool(consumeId.hasSuffix(":CHK"))
                if !t["stmp"].truthy {
                    let ts = String(consumeId.dropLast(4))
                    out["timestamp"] = .number(!ts.isEmpty && ts.allSatisfy({ $0.isASCII && $0.isNumber }) ? Double(ts)! : DB.fromBase62(ts))
                }
            }
        } else if let renamed = ticketKeys[k] {
            out[renamed] = v
        } else {
            out[k] = v
        }
    }
    return out
}

/// "public" -> 0, "authorized" -> 1, an integer 0..99, or a newsletter group name.
func newsletterGroup(_ group: JSON?, allowNull: Bool = false) throws -> JSON {
    guard let g = group, !g.isNull else {
        if allowNull { return .null }
        throw paramError("\"group\" is required.")
    }
    if g == .string("public") { return 0 }
    if g == .string("authorized") { return 1 }
    if let n = g.number {
        if n != n.rounded() || n < 0 || n > 99 { throw paramError("\"group\" should be an integer between 0 and 99.") }
        return .number(n)
    }
    let reserved: Set<String> = ["tp", "admin", "public", "authorized", "newsletter", "forward", "all", "true", "false", "null"]
    if let s = g.string, Rx.match("^[a-z0-9]{2,20}$", s), Rx.search("[a-z]", s), !Rx.match("^[0-9]+e[0-9]+$", s), !reserved.contains(s) {
        return g
    }
    throw paramError("Newsletter group name must be 2-20 lowercase alphanumeric characters, contain a letter, and not be a reserved name.")
}

func subscriptionRow(_ s: JSON) -> JSON {
    let sub = s["sub"]?.string
    let grp = s["grp"]?.string ?? ""
    let parts = sub?.components(separatedBy: "#") ?? []
    var row: JSONObject = [
        "subscriber": parts.count > 2 ? .string(parts[2]) : (s["subscriber"] ?? .null),
        "subscription": !parts.isEmpty ? .string(parts[0]) : (s["subscription"] ?? .null),
        "timestamp": (s["timestamp"].truthy ? s["timestamp"] : s["stmp"]) ?? .null,
        "blocked": .bool(s["blocked"].truthy || grp.hasPrefix("N")),
    ]
    if let opt = s["opt"]?.object { for (k, v) in opt { row[k] = v } }
    return .object(row)
}

extension Skapi {
    private func target(_ params: JSON) throws -> String {
        guard let u = params["user_id"] else { throw paramError("Key \"user_id\" is required.") }
        return try notSelf(u)
    }

    private func notSelf(_ uid: JSON, _ field: String = "\"user_id\"") throws -> String {
        if userObj != nil, uid.string == me { throw paramError("\"user_id\" cannot be the user's own ID.") }
        return try DB.userId(uid, field)
    }

    // ---- newsletters ------------------------------------------------------------------------------

    /// Subscribes to the project's newsletters of one group. Signed in: the user's verified e-mail.
    /// Signed out: params["email"], which gets a confirmation e-mail first.
    @discardableResult
    public func subscribeNewsletter(_ params: JSON) async throws -> JSON {
        try await ensureConnection()
        try refuseAnonymous("subscribe to newsletters")
        let params = params.object ?? JSONObject()
        let signedIn = await self.signedIn()
        if !params.contains("group") { throw paramError("Key \"group\" is required.") }
        if !signedIn && !params.contains("email") { throw paramError("Key \"email\" is required.") }
        var body = JSONObject()
        if let e = params["email"] {
            if let list = e.array, !list.isEmpty {
                body["email"] = list.count == 1 ? .string(try Check.email(list[0])) : .array(try list.map { .string(try Check.email($0)) })
            } else {
                body["email"] = .string(try Check.email(e.isArray ? .string("") : e))
            }
        }
        body["group"] = try newsletterGroup(params["group"])
        if let r = params["redirect"] { body["redirect"] = try Check.url(r) }
        return try await call(signedIn ? "subscribe-newsletter" : "subscribe-public-newsletter", .object(body), auth: signedIn)
    }

    /// Unsubscribes the signed-in user from one group, or from every group with nil.
    @discardableResult
    public func unsubscribeNewsletter(group: JSON?) async throws -> JSON {
        try await ensureConnection()
        try refuseAnonymous("subscribe to newsletters")
        return try await call("subscribe-newsletter", ["action": "unsubscribe", "group": try newsletterGroup(group, allowNull: true)], auth: true)
    }

    /// Newsletters sent to a group, newest first by default. Each has a url to its content.
    public func getNewsletters(_ params: JSON? = nil, fetchOptions: FetchOptions? = nil) async throws -> JSON {
        try await ensureConnection()
        let admin = isAdmin()
        var fo = fetchOptions?.object ?? JSONObject()
        var params = params?.object
        if params == nil {
            if !fo.contains("ascending") { fo["ascending"] = false }
            params = ["searchFor": "timestamp", "value": .number(nowMs()), "condition": "<", "group": "public"]
        }
        let p = params!
        for key in ["searchFor", "value", "group"] where !p.contains(key) { throw paramError("Key \"\(key)\" is required.") }
        let fields = ["message_id", "timestamp", "subject", "complaint", "read", "bounced"]
        guard let searchFor = p["searchFor"]?.string, fields.contains(searchFor) else {
            throw paramError("\(jd(p["searchFor"])) is invalid in \"searchFor\". allowed types or values are: " + fields.map { jd(.string($0)) }.joined(separator: ", ") + ".")
        }
        let value = p["value"]!
        let wantsStr = searchFor == "message_id" || searchFor == "subject"
        if (wantsStr && !value.isString) || (!wantsStr && !value.isNumber) {
            throw paramError("\"value\" type does not match the type of \"\(searchFor)\" index.")
        }
        if value == .string("") { throw paramError("\"value\" should not be empty string.") }
        var body: JSONObject = ["searchFor": .string(searchFor), "value": value]
        if let r = p["range"] {
            if DB.typeOf(r) != DB.typeOf(value) { throw paramError("\"range\" should match type of \"value\".") }
            body["range"] = r
        }
        let conditions = [">", ">=", "=", "<", "<=", "gt", "gte", "eq", "lt", "lte"]
        body["condition"] = .string(p["condition"]?.string.flatMap { conditions.contains($0) ? $0 : nil } ?? "=")
        let group = try newsletterGroup(p["group"])
        if let n = group.number, n >= 1 {
            if !(await signedIn()) { throw paramError("User should be logged in.") }
            if !admin && n > (userObj?["access_group"]?.number ?? 0) { throw paramError("User has no access.") }
        }
        body["group"] = group
        let signedIn = await self.signedIn()
        var res: JSON
        if group == .number(0) || (group.isString && !signedIn) {
            res = try await call("get-public-newsletters", .object(body), auth: signedIn, method: "GET", fetchOptions: fo)
        } else {
            res = try await call("get-newsletters", .object(body), auth: true, method: "GET", fetchOptions: fo)
        }
        if let list = res["list"]?.array {
            let defaults: [(String, String, JSON)] = [("message_id", "mid", ""), ("timestamp", "stmp", 0), ("complaint", "cmpl", 0), ("read", "read", 0),
                                                      ("subject", "subj", ""), ("bounced", "bnce", ""), ("url", "url", ""), ("delivered", "delv", 0),
                                                      ("group", "grp", group), ("dry", "dry", false), ("sent", "sent", 0)]
            res["list"] = .array(list.map { row in
                var item = JSONObject()
                for (k, src, def) in defaults { item[k] = row[src].truthy ? row[src]! : def }
                item["bounced"] = .string(item["bounced"]!.pyString)
                item["dry"] = .bool(item["dry"]!.truthy)
                if !item["sent"].truthy { item["sent"] = nil }
                return .object(item)
            })
        }
        return res
    }

    /// The signed-in user's newsletter subscriptions: [["timestamp", "group", "subscribed_email", "active"]].
    public func getNewsletterSubscription(_ params: JSON? = nil, fetchOptions: FetchOptions? = nil) async throws -> JSON {
        try await ensureConnection()
        try refuseAnonymous("subscribe to newsletters")
        let params = params?.object ?? JSONObject()
        var body = JSONObject()
        if let u = params["user_id"] {
            if u.string != me && !isAdmin() { throw paramError("No access.") }
            body["user_id"] = u
        }
        if params.contains("group") { body["group"] = try newsletterGroup(params["group"], allowNull: true) }
        var data = try await call("get-newsletter-subscription", .object(body), auth: true, fetchOptions: fetchOptions?.object)
        let hasList = data.object?.contains("list") == true
        let rows = hasList ? data["list"] : data
        var out: [JSON] = []
        for r in rows?.array ?? [] {
            let parts = (r["subt"]?.pyString ?? "").components(separatedBy: "#")
            var token = parts[0]
            let active = !token.hasPrefix("@")
            while token.hasPrefix("@") { token.removeFirst() }
            var item: JSONObject = ["timestamp": r["stmp"] ?? .null,
                                    "group": !token.isEmpty && token.allSatisfy({ $0.isASCII && $0.isNumber }) ? .number(Double(token)!) : .string(token),
                                    "subscribed_email": .string(parts.count > 1 ? parts[1] : ""), "active": .bool(active)]
            if let t = r["email_token"]?.string, !t.isEmpty { item["subscriber_token"] = .string(t) }
            out.append(.object(item))
        }
        if hasList {
            data["list"] = .array(out)
            return data
        }
        return .array(out)
    }

    // ---- subscriptions between users -------------------------------------------------------------

    /// Subscribes the signed-in user to another user: ["user_id", "get_feed"?, "get_notified"?, "get_email"?].
    @discardableResult
    public func subscribe(_ params: JSON) async throws -> JSON {
        try await requireSession()
        let params = params.object ?? JSONObject()
        guard let u = params["user_id"] else { throw paramError("Key \"user_id\" is required.") }
        let targetId = try notSelf(u)
        var option = JSONObject()
        for k in ["get_feed", "get_notified"] {
            if let v = params[k] {
                guard v.isBool else { throw paramError("\(jd(v)) is invalid in \"\(k)\". allowed type or value is: Type<boolean>.") }
                option[k] = v
            }
        }
        if let ge = params["get_email"] {
            if ge.truthy && !(userObj?["email"].truthy == true && userObj?["email_verified"]?.bool == true) {
                throw paramError("User has no verified email address.")
            }
            option["get_email"] = .bool(ge.truthy)
        }
        let s = try await call("subscription", ["subscribe": .string(targetId), "option": .object(option)], auth: true)
        guard s.isObject else { throw SkapiError("The subscription is blocked.", code: "INVALID_REQUEST") }
        return subscriptionRow(s)
    }

    @discardableResult
    public func unsubscribe(_ params: JSON) async throws -> JSON {
        try await requireSession()
        return try await call("subscription", ["unsubscribe": .string(try target(params))], auth: true)
    }

    /// Stops a user from subscribing to the signed-in user (and from getting their feed).
    @discardableResult
    public func blockSubscriber(_ params: JSON) async throws -> JSON {
        try await requireSession()
        return try await call("subscription", ["block": .string(try target(params))], auth: true)
    }

    @discardableResult
    public func unblockSubscriber(_ params: JSON) async throws -> JSON {
        try await requireSession()
        return try await call("subscription", ["unblock": .string(try target(params))], auth: true)
    }

    /// Who a user subscribes to (["subscriber": id]) or who subscribes to a user (["subscription": id]).
    public func getSubscriptions(_ params: JSON, fetchOptions: FetchOptions? = nil) async throws -> JSON {
        try await requireSession()
        let params = params.object ?? JSONObject()
        var body = JSONObject()
        if params.contains("subscriber") { body["subscriber"] = .string(try DB.userId(params["subscriber"], "User ID in \"subscriber\"")) }
        // any user, yourself included: your own id lists your own subscribers
        if params.contains("subscription") { body["subscription"] = .string(try DB.userId(params["subscription"], "User ID in \"subscription\"")) }
        if let b = params["blocked"] {
            guard b.isBool else { throw paramError("\(jd(b)) is invalid in \"blocked\". allowed type or value is: Type<boolean>.") }
            body["blocked"] = b
        }
        if !body["subscriber"].truthy && !body["subscription"].truthy {
            throw paramError("At least either \"subscriber\" or \"subscription\" should have a value.")
        }
        var res = try await call("get-subscription", .object(body), auth: true, fetchOptions: fetchOptions?.object)
        if let list = res["list"]?.array { res["list"] = .array(list.map(subscriptionRow)) }
        return res
    }

    /// Records the users you subscribe to (with get_feed on) posted to their feed, newest first.
    public func getFeed(_ params: JSON? = nil, fetchOptions: FetchOptions? = nil) async throws -> JSON {
        try await requireSession()
        let params = params?.object ?? JSONObject()
        var body = JSONObject()
        if let v = params["access_group"] {
            let g: JSON = v == .string("authorized") ? 1 : v == .string("public") ? 0 : v
            guard let n = g.number else { throw paramError("\"access_group\" should be type number.") }
            if n < 0 { throw paramError("\"access_group\" should be zero or a positive number.") }
            if n > (userObj?["access_group"]?.number ?? 0) { throw paramError("User has no access.") }
            body["access_group"] = g
        }
        var res = try await call("get-feed", .object(body), auth: true, fetchOptions: fetchOptions?.object)
        if let list = res["list"]?.array {
            var out: [JSON] = []
            for r in list { out.append(try await normalizeRecord(r)) }
            res["list"] = .array(out)
        }
        return res
    }

    // ---- tickets ------------------------------------------------------------------------------------

    /// The project's tickets (or one, with ["ticket_id": ...]) as a signed-in user sees them.
    public func getTickets(_ params: JSON? = nil, fetchOptions: FetchOptions? = nil) async throws -> JSON {
        var body: JSONObject = ["exec": "list"]
        for (k, v) in params?.object ?? JSONObject() { body[k] = v }
        var res = try await call("ticket", .object(body), auth: true, fetchOptions: fetchOptions?.object)
        if let list = res["list"]?.array { res["list"] = .array(list.map { $0.object.map { .object(mapTicket($0)) } ?? $0 }) }
        return res
    }

    /// The signed-in user's own ticket calls (each with ticket_id, consume_id and timestamp).
    public func getConsumedTickets(_ params: JSON? = nil, fetchOptions: FetchOptions? = nil) async throws -> JSON {
        var body: JSONObject = ["exec": "consumed"]
        for (k, v) in params?.object ?? JSONObject() { body[k] = v }
        var res = try await call("ticket", .object(body), auth: true, fetchOptions: fetchOptions?.object)
        if let list = res["list"]?.array { res["list"] = .array(list.map { $0.object.map { .object(mapTicket($0)) } ?? $0 }) }
        return res
    }
}
