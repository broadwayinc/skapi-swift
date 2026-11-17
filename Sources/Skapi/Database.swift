import Foundation

/// Database methods, ported from skapi-py (_database.py) and skapi-js (src/methods/database.ts):
/// same validation, same request bodies, same decoding of the records the server returns.
extension Skapi {
    func scope(_ service: JSON? = nil, _ owner: JSON? = nil) -> String {
        let s = service?.string.flatMap { $0.isEmpty ? nil : $0 } ?? self.service
        let o = owner?.string.flatMap { $0.isEmpty ? nil : $0 } ?? self.owner
        return "\(s)/\(o)"
    }

    /// Drops every remembered unique_id that points at one of these records (renamed or deleted).
    func forgetUniqueIds(_ scope: String, _ recordIds: Set<String>) {
        guard var known = myUniqueIds[scope] else { return }
        for (uid, rid) in known where recordIds.contains(rid) { known[uid] = nil }
        myUniqueIds[scope] = known
    }

    /// After a write: the record's current unique_id, and none of its earlier ones.
    func rememberUniqueId(_ scope: String, _ record: JSON) {
        guard let rid = record["record_id"]?.string, !rid.isEmpty else { return }
        forgetUniqueIds(scope, [rid])
        if let uid = record["unique_id"]?.string, !uid.isEmpty { myUniqueIds[scope, default: [:]][uid] = rid }
    }

    /// A record file url getFile gave out may come back to deleteFiles or remove_bin. The server
    /// removes the stored file url by exact string, so the url given out is mapped back to the exact
    /// url it was made from.
    func rememberHandedOutURL(_ handedOut: String, _ requested: String) {
        let base = handedOut.components(separatedBy: "?")[0]
        let raw = requested.components(separatedBy: "?")[0]
        if base.hasPrefix("https://") && (base != raw || DB.undoURLPathEncoding(base) != base) {
            handedOutFileUrls[base] = raw
        }
    }

    /// The form the server stores a record file url in (see skapi-py _stored_record_file_url).
    func storedRecordFileURL(_ url: String) -> String {
        let base = url.components(separatedBy: "?")[0]
        if let known = handedOutFileUrls[base] { return known }
        return url.contains("?") ? DB.undoURLPathEncoding(base) : base
    }

    func isAdmin() -> Bool {
        guard let u = userObj else { return false }
        return u["service"]?.string == service && u["owner"]?.string == "skapi"
    }

    func requireLoginGate(_ method: String) async throws {
        let conn = try await ensureConnection()
        if !(await signedIn()), conn["opt"]?["require_login"] == .bool(true) {
            throw SkapiError("This project requires users to sign in before reading its database, so \"\(method)\" is not available to a signed-out visitor.",
                             code: "REQUIRE_LOGIN")
        }
    }

    // ---- query builder ----------------------------------------------------------------------

    func buildQuery(_ queryIn: JSON?, isDelete: Bool) async throws -> (JSONObject, String?) {
        var query = queryIn?.object ?? JSONObject()
        let scope = self.scope(query["service"], query["owner"])
        var isReferenceFetch: String?
        let signedIn = await self.signedIn()

        if let idQuery = try DB.recordOrUniqueId(query, isDelete: isDelete) {
            query = idQuery
            let single = query["record_id"] ?? query["unique_id"] ?? .null
            if let list = single.array {
                let ids = list.compactMap { $0.string }
                if query.contains("unique_id") {
                    for uid in ids { myUniqueIds[scope]?[uid] = nil }
                } else if isDelete {
                    forgetUniqueIds(scope, Set(ids))
                }
                return (query, nil)
            }
            let s = single.string ?? ""
            isReferenceFetch = s
            if let key = cachedPrivateKey(s) { query["private_key"] = .string(key) }
            let cached = myUniqueIds[scope]?[s]
            if isDelete {
                myUniqueIds[scope]?[s] = nil
                if query.contains("record_id") { forgetUniqueIds(scope, [s]) }
            } else if let c = cached {
                query["record_id"] = .string(c)
            }
            return (query, isReferenceFetch)
        }

        let admin = isAdmin()
        var refUserIsMe = false
        if let ref = query["reference"]?.object {
            if let rid = (ref["record_id"].truthy ? ref["record_id"] : ref["unique_id"]), rid.truthy {
                isReferenceFetch = rid.pyString
                if let key = cachedPrivateKey(rid.pyString) { query["private_key"] = .string(key) }
                query["reference"] = rid
            } else if let u = ref["user_id"], u.truthy {
                refUserIsMe = userObj != nil && u.string == me
                query["reference"] = u
            }
        }
        if let t = query["table"]?.string {
            query["table"] = ["name": .string(t), "access_group": 0]
        }
        if !admin, let t = query["table"]?.object, t["access_group"] == nil || t["access_group"] == .null {
            throw DB.err("\"table.access_group\" is required: a table is always { name, access_group }. " +
                         "To read what references a record in every table, send \"reference\" without \"table\".")
        }
        if var index = query["index"]?.object, index.contains("range"), index.contains("condition") {
            index["range"] = nil
            query["index"] = .object(index)
        }
        let readsByReference = !isDelete && signedIn && (isReferenceFetch.map { !$0.isEmpty } ?? false || (query["reference"]?.string.map { !$0.isEmpty } ?? false))
        let requiredTable = !(refUserIsMe || admin || readsByReference)

        var out = JSONObject()
        if let t = query["table"] {
            guard var nt = t.object else { throw DB.err("\(jd(t)) is invalid in \"table\". allowed type or value is: Type<object>.") }
            if nt.contains("name") { nt["name"] = .string(try DB.tableName(nt["name"])) }
            if nt.contains("access_group") { nt["access_group"] = try DB.accessGroupIn(nt["access_group"], signedIn: signedIn) }
            if nt.contains("subscription") { nt["subscription"] = .string(try DB.userId(nt["subscription"], "User ID in \"subscription\"")) }
            out["table"] = .object(nt)
        } else if requiredTable {
            throw DB.err("Key \"table\" is required.")
        }
        if let r = query["reference"] {
            guard r.isString else { throw DB.err("\(jd(r)) is invalid in \"reference\". allowed type or value is: Type<string>.") }
            out["reference"] = r
        }
        if let i = query["index"] {
            guard var ni = i.object else { throw DB.err("\(jd(i)) is invalid in \"index\". allowed type or value is: Type<object>.") }
            let original = ni
            let rawName = original["name"]?.string
            if original.contains("name") {
                ni["name"] = (rawName.map { DB.specialIndex.contains($0) } ?? false) ? original["name"]! : .string(try DB.indexName(original["name"]))
            }
            if var v = original["value"] {
                if ["$updated", "$uploaded", "$referenced_count"].contains(rawName ?? "") {
                    if !v.isNumber { throw DB.err("\"index.value\" should be type: number.") }
                } else if rawName == "$user_id" {
                    v = .string(try DB.userId(v))
                } else if v == .string("") {
                    v = ""
                } else if v.isString, let n = rawName, n.hasSuffix(".") {
                    v = .string(try DB.validateString(v, "index.value", allowEmpty: true, escape: true))
                } else {
                    v = try DB.indexValue(v)
                }
                ni["value"] = v
            }
            if original.contains("condition") { ni["condition"] = .string(try DB.condition(original["condition"], DB.conditions, "condition")) }
            if let r0 = original["range"] {
                guard let value = original["value"] else { throw DB.err("\"index.value\" is required.") }
                if rawName == "$record_id" { throw DB.err("Cannot do \"index.range\" on $record_id") }
                if DB.typeOf(value) != DB.typeOf(r0) { throw DB.err("\"index.range\" type should match the type of \"index.value\".") }
                var r = r0
                if r.isString {
                    r = .string(try DB.validateString(r, "index.range", allowEmpty: true, escape: rawName?.hasSuffix(".") ?? false))
                }
                ni["range"] = r
            }
            out["index"] = .object(ni)
        }
        if let tag = query["tag"], !tag.isNull {
            guard tag.isString else { throw DB.err("\"tag\" should be type: string.") }
            out["tag"] = .string(try DB.tagName(tag))
        }
        for key in ["private_key", "service", "owner"] {
            if let v = query[key] {
                guard v.isString else { throw DB.err("\(jd(v)) is invalid in \"\(key)\". allowed type or value is: Type<string>.") }
                out[key] = v
            }
        }
        return (out, isReferenceFetch)
    }

    // ---- reads ------------------------------------------------------------------------------

    /// Records by id, unique id, table, index, tag or reference. Returns ["list": [...], "startKey", "endOfList", ...].
    public func getRecords(_ query: JSON? = nil, fetchOptions: FetchOptions? = nil) async throws -> JSON {
        try await getRecords(query, fetchOptions: fetchOptions?.object)
    }

    func getRecords(_ query: JSON?, fetchOptions: JSONObject?) async throws -> JSON {
        try await requireLoginGate("getRecords")
        let (q, refId) = try await buildQuery(query, isDelete: false)
        let signedIn = await self.signedIn()
        var result = try await call("get-records", .object(q), auth: signedIn, method: signedIn ? "POST" : "GET", fetchOptions: fetchOptions)
        if let r = refId, !r.isEmpty, let k = result["reference_private_key"]?.string { privateAccessKey[r] = k }
        if let list = result["list"]?.array {
            var out: [JSON] = []
            for r in list { out.append(try await normalizeRecord(r)) }
            result["list"] = .array(out)
        }
        return result
    }

    /// Deletes your records (or any, as an admin) by id, unique id, or query.
    @discardableResult
    public func deleteRecords(_ query: JSON, fetchOptions: FetchOptions? = nil) async throws -> JSON {
        try await ensureConnection()
        let (q, refId) = try await buildQuery(query, isDelete: true)
        var result = try await call("del-records", .object(q), auth: true, fetchOptions: fetchOptions?.object)
        if let r = refId, !r.isEmpty, let k = result["reference_private_key"]?.string { privateAccessKey[r] = k }
        if let list = result["list"]?.array {
            var out: [JSON] = []
            for r in list {
                if r.isObject, let n = try? await normalizeRecord(r, skipDataFetch: true, skipBinResolve: true) { out.append(n) } else { out.append(r) }
            }
            result["list"] = .array(out)
            // a delete by query names no ids up front: the unique_ids remembered for the records it deleted are dropped here
            var deleted = Set<String>()
            for r in out { if let id = (r["record_id"]?.string).flatMap({ $0.isEmpty ? nil : $0 }) ?? r["rec"]?.string, !id.isEmpty { deleted.insert(id) } }
            if !deleted.isEmpty { forgetUniqueIds(scope(query["service"], query["owner"]), deleted) }
        }
        if let m = result["message"], m.truthy { return m }
        return result
    }

    /// The project's tables, with their record counts.
    public func getTables(_ query: JSON? = nil, fetchOptions: FetchOptions? = nil) async throws -> JSON {
        let query = query?.object ?? JSONObject()
        var p = JSONObject()
        if query.contains("table") { p["table"] = .string(try DB.tableName(query["table"], "table", allowEmpty: true)) }
        if query.contains("condition") { p["condition"] = .string(try DB.condition(query["condition"], DB.conditionsNE)) }
        for k in ["service", "owner"] where query.contains(k) { p[k] = query[k] }
        var res = try await call("get-table", .object(p), auth: await signedIn(), fetchOptions: fetchOptions?.object)
        let names = ["pv": "private", "00": "public", "01": "authorized", "99": "admin"]
        if let list = res["list"]?.array {
            res["list"] = .array(list.map { itemJSON in
                guard var item = itemJSON.object else { return itemJSON }
                for k in item.keys where k.hasPrefix("grp_") {
                    let x = String(k.dropFirst(4))
                    let v = item.removeValue(forKey: k)
                    item["number_of_records_in_access_group_\(names[x] ?? x)"] = v
                }
                for (old, new) in [("cnt_rec", "number_of_records"), ("tbl", "table"), ("srvc", "service")] where item.contains(old) {
                    item[new] = item.removeValue(forKey: old)
                }
                if let t = item["table"] { item["table"] = DB.decodeDelimiters(t) }
                return .object(item)
            })
        }
        return res
    }

    /// The tags used in a table, with their record counts.
    public func getTags(_ query: JSON? = nil, fetchOptions: FetchOptions? = nil) async throws -> JSON {
        let query = query?.object ?? JSONObject()
        var p = JSONObject()
        if query.contains("table") { p["table"] = .string(try DB.tableName(query["table"], "table", allowEmpty: true)) }
        if query.contains("tag") { p["tag"] = .string(try DB.tagName(query["tag"], "tag", allowEmpty: true)) }
        if query.contains("condition") { p["condition"] = .string(try DB.condition(query["condition"], DB.conditionsNE)) }
        for k in ["service", "owner"] where query.contains(k) { p[k] = query[k] }
        var res = try await call("get-tag", .object(p), auth: await signedIn(), fetchOptions: fetchOptions?.object)
        if let list = res["list"]?.array {
            res["list"] = .array(list.map { item in
                let parts = (item["tag"]?.string ?? "").components(separatedBy: "/")
                return ["table": .string(DB.decodeDelimiters(parts.count > 1 ? parts[1] : "")), "tag": .string(DB.decodeDelimiters(parts[0])),
                        "number_of_records": item["cnt_rec"] ?? .null]
            })
        }
        return res
    }

    /// The indexes used in a table, with counts, totals and averages.
    public func getIndexes(_ query: JSON, fetchOptions: FetchOptions? = nil) async throws -> JSON {
        let query = query.object ?? JSONObject()
        if !query["table"].truthy { throw DB.err("\"table\" is required.") }
        var p: JSONObject = ["table": .string(try DB.tableName(query["table"], "table", allowEmpty: true))]
        if query.contains("index") { p["index"] = .string(try DB.indexName(query["index"], "index.name")) }
        if let o = query["order"] {
            guard var no = o.object else { throw DB.err("\(jd(o)) is invalid in \"order\". allowed type or value is: Type<object>.") }
            let orig = no
            if orig.contains("by") { no["by"] = .string(try DB.condition(orig["by"], DB.orderBy, "by")) }
            if var v = orig["value"] {
                if orig["by"] == .string("index_name"), v.isString {
                    v = .string(try DB.validateString(v, "order.value", allowEmpty: true, escape: true))
                } else if !(v.isString || v.isNumber || v.isBool) {
                    throw DB.err("\"order.value\" should be type: <string | number | boolean>.")
                }
                no["value"] = v
            }
            if orig.contains("condition") { no["condition"] = .string(try DB.condition(orig["condition"], DB.conditionsNE)) }
            if !no.contains("by") { throw DB.err("\"order.by\" is required.") }
            if no.contains("condition") && !no.contains("value") { throw DB.err("\"value\" is required for \"condition\".") }
            if let idx = p["index"]?.string, !idx.hasSuffix(".") {
                throw DB.err("\"index\" should be a parent index name of the compound index when using \"order.by\"")
            }
            p["order"] = .object(no)
        }
        for k in ["service", "owner"] where query.contains(k) { p[k] = query[k] }
        var res = try await call("get-index", .object(p), auth: await signedIn(), fetchOptions: fetchOptions?.object)
        if let list = res["list"]?.array {
            let rename = [("cnt_bool", "boolean_count"), ("cnt_numb", "number_count"), ("totl_numb", "total_number"), ("totl_bool", "total_bool"),
                          ("avrg_numb", "average_number"), ("avrg_bool", "average_bool"), ("cnt_str", "string_count")]
            res["list"] = .array(list.map { i in
                let parts = (i["idx"]?.string ?? "").components(separatedBy: "/")
                var item: JSONObject = ["table": .string(DB.decodeDelimiters(parts.count > 1 ? parts[1] : "")),
                                        "index": .string(DB.decodeDelimiters(parts.count > 2 ? parts[2] : "")),
                                        "number_of_records": i["cnt_rec"] ?? .null]
                for (k, v) in rename { if let x = i[k] { item[v] = x } }
                return .object(item)
            })
        }
        return res
    }

    /// Unique IDs in use, and the records they name.
    public func getUniqueId(_ query: JSON? = nil, fetchOptions: FetchOptions? = nil) async throws -> JSON {
        let query = query?.object ?? JSONObject()
        var p = JSONObject()
        if let u = query["unique_id"] {
            guard u.isString else { throw DB.err("\(jd(u)) is invalid in \"unique_id\". allowed type or value is: Type<string>.") }
            p["unique_id"] = u
        }
        if query.contains("condition") { p["condition"] = .string(try DB.condition(query["condition"], DB.conditionsNE)) }
        for k in ["service", "owner"] where query.contains(k) { p[k] = query[k] }
        var res = try await call("get-uniqueid", .object(p), auth: await signedIn(), fetchOptions: fetchOptions?.object)
        if let list = res["list"]?.array {
            res["list"] = .array(list.map { ["unique_id": $0["unq"] ?? .null, "record_id": $0["rec"] ?? .null] })
        }
        return res
    }

    // ---- writes -----------------------------------------------------------------------------

    /// Validated config (what goes on the wire) and the reference id to remember a private key under.
    func setupPostConfig(_ configIn: JSON?) async throws -> (JSONObject, String?) {
        guard var c = configIn?.object else { throw DB.err("\"config\" argument is required.") }
        let signedIn = await self.signedIn()
        if !c["record_id"].truthy && !c["table"].truthy { throw DB.err("\"table.name\" is required.") }
        if let t = c["table"]?.string {
            c["table"] = c["record_id"].truthy ? ["name": .string(t)] : ["name": .string(t), "access_group": 0]
        }
        let scope = self.scope(c["service"], c["owner"])
        var out = JSONObject()
        var isReferencePost: String?

        if let rid = c["record_id"], !rid.isNull {
            if let s = rid.string, let cached = myUniqueIds[scope]?[s] { out["record_id"] = .string(cached) }
            else { out["record_id"] = .string(try DB.validateString(rid, "record_id", maxLength: 0)) }
        }
        if let u = c["unique_id"] {
            if !u.isNull && !u.isString { throw DB.err("\(jd(u)) is invalid in \"unique_id\". allowed types or values are: Type<string>, null.") }
            out["unique_id"] = u
        }
        if let r = c["readonly"] {
            guard r.isBool else { throw DB.err("\(jd(r)) is invalid in \"readonly\". allowed type or value is: Type<boolean>.") }
            out["readonly"] = r
        }
        if let t = c["table"], !t.isNull {
            guard var nt = t.object else { throw DB.err("\(jd(t)) is invalid in \"table\". allowed types or values are: Type<string>, Type<object>.") }
            if nt.contains("name") { nt["name"] = .string(try DB.tableName(nt["name"])) }
            if nt.contains("access_group") { nt["access_group"] = try DB.accessGroupIn(nt["access_group"], signedIn: signedIn) }
            if let sub = nt["subscription"], !sub.isNull {
                guard let so = sub.object else { throw DB.err("\"table.subscription\" should be type: <object | null>.") }
                for (k, v) in so where ["is_subscription_record", "upload_to_feed", "notify_subscribers", "feed_referencing_records",
                                        "notify_referencing_records"].contains(k) && !v.isBool {
                    throw DB.err("\"table.subscription.\(k)\" should be type: <boolean>.")
                }
            }
            out["table"] = .object(nt)
        }
        if let n = c["notification"], !n.isNull {
            guard let no = n.object else { throw DB.err("\"notification\" should be an object with \"title\" and \"body\".") }
            for k in ["title", "body"] {
                guard let s = no[k]?.string, !s.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { throw DB.err("\"notification.\(k)\" is required.") }
            }
            out["notification"] = ["title": no["title"]!, "body": no["body"]!]
        }
        if let src = c["source"], !src.isNull {
            var s = src.object ?? JSONObject()
            if let v = s["referencing_limit"], !v.isNull {
                guard let n = v.number else { throw DB.err("\"reference_limit\" should be type: <number | null>") }
                if n < 0 { throw DB.err("\"reference_limit\" should be >= 0") }
                if n > 4503599627370546 { throw DB.err("\"reference_limit\" should be <= 4503599627370546") }
            }
            for k in ["prevent_multiple_referencing", "can_remove_referencing_records", "only_granted_can_reference", "allow_granted_to_grant_others"] {
                if let v = s[k], !v.isBool { throw DB.err("\"source.\(k)\" should be type: <boolean>.") }
            }
            if let r = s["referencing_index_restrictions"] {
                if !r.truthy {
                    s["referencing_index_restrictions"] = .null
                } else {
                    let items = r.array ?? [r]
                    var fixed: [JSON] = []
                    for item in items {
                        let io = item.object ?? JSONObject()
                        if !io.contains("name") { throw DB.err("Key \"name\" is required.") }
                        if io.contains("range") { throw DB.err("Index restriction \"range\" type should match the type of \"value\".") }
                        var ni = io
                        ni["name"] = .string(try DB.indexName(io["name"], "\"name\" in \"index_restrictions\""))
                        if io.contains("value") { ni["value"] = try DB.indexValue(io["value"]) }
                        let cond = io["condition"]?.string
                        ni["condition"] = (cond.map { DB.conditionsNE.contains($0) } ?? false) ? .string(cond!) : .null
                        fixed.append(.object(ni))
                    }
                    s["referencing_index_restrictions"] = .array(fixed)
                }
            }
            out["source"] = .object(s)
        }
        if let ref = c["reference"] {
            if ref.isNull {
                out["reference"] = ["record_id": nil]
            } else if !ref.truthy {
            } else if let s = ref.string {
                let r = myUniqueIds[scope]?[s] ?? s
                out["reference"] = .string(r)
                isReferencePost = r
            } else if var nr = ref.object {
                if let rid = nr["record_id"], !rid.isNull {
                    nr["record_id"] = .string(try DB.validateString(rid, "reference.record_id", maxLength: 0, alphanumeric: true))
                }
                if let u = nr["unique_id"], !u.isString { throw DB.err("\"reference.unique_id\" should be type: <string>.") }
                out["reference"] = .object(nr)
            } else {
                throw DB.err("\"reference\" should be type: <string | object>.")
            }
        }
        if let i = c["index"] {
            if i.isNull {
                out["index"] = .null
            } else {
                guard var ni = i.object else { throw DB.err("\"index\" should be type: <object | null>.") }
                if ni.contains("name") { ni["name"] = .string(try DB.indexName(ni["name"])) }
                if ni.contains("value") { ni["value"] = try DB.indexValue(ni["value"]) }
                out["index"] = .object(ni)
            }
        }
        if let tags = c["tags"] {
            if tags.isNull {
                out["tags"] = .null  // removes every tag, as in skapi-js
            } else {
                var list: [JSON]
                if let s = tags.string { list = s.components(separatedBy: ",").map { .string($0.trimmingCharacters(in: .whitespacesAndNewlines)) } }
                else if let a = tags.array { list = a }
                else { throw DB.err("\"tag\" should be type: <string | string[]>.") }
                out["tags"] = .array(try list.map { .string(try DB.tagName($0)) })
            }
        }
        if let rb = c["remove_bin"] {
            // JavaScript falsiness: null, false, 0 and "" mean null; an empty list removes nothing
            if rb.isNull || rb == .bool(false) || rb == .number(0) || rb == .string("") {
                out["remove_bin"] = .null
            } else {
                guard let list = rb.array else { throw DB.err("\"remove_bin\" should be type: <string[] | BinaryFile[] | null>") }
                var fixed: [JSON] = []
                for item in list {
                    if let s = item.string {
                        // the stored file url, as deleteFiles sends it
                        fixed.append(.string(storedRecordFileURL(s)))
                    } else if let o = item.object, o["url"].truthy, o["size"].truthy, o["filename"].truthy,
                              let parts = Check.splitURL(o["url"]?.string ?? "") {
                        fixed.append(.string("\(parts.scheme)://\(parts.netloc)/\(o["path"]?.pyString ?? "")"))
                    } else {
                        throw DB.err("\"remove_bin\" should be type: <string[] | BinaryFile[] | null>")
                    }
                }
                out["remove_bin"] = .array(fixed)
            }
        }
        for key in ["service", "owner"] where c.contains(key) { out[key] = c[key] }

        if !signedIn {
            let t = out["table"]?.object ?? JSONObject()
            if out["record_id"].truthy { throw DB.err("Public users cannot update existing records.", "INVALID_REQUEST") }
            if !(t["access_group"] == .string("public") || t["access_group"] == .number(0)) {
                throw DB.err("Public users can only post records to public tables.", "INVALID_REQUEST")
            }
            if (t["subscription"]?.object?.values ?? []).contains(where: { $0.truthy }) {
                throw DB.err("Public users cannot post subscription records.", "INVALID_REQUEST")
            }
            if out["remove_bin"].truthy { throw DB.err("Public users cannot remove files from records.", "INVALID_REQUEST") }
            if out["unique_id"].truthy { throw DB.err("Public users cannot set unique_id for records.", "INVALID_REQUEST") }
        }
        return (out, isReferencePost)
    }

    /// Creates a record, or updates one when config has "record_id".
    /// data: any JSON value. Leave it out (nil) on an update to keep the stored data; `.null` stores null.
    /// config: ["table": ["name", "access_group"], "index", "tags", "reference", "unique_id", "readonly", "source", "remove_bin", ...].
    /// files: files to attach, listed in the record's "bin".
    @discardableResult
    public func postRecord(_ data: JSON? = nil, config: JSON, files: [UploadFile]? = nil) async throws -> JSON {
        try await ensureConnection()
        var (conf, isReferencePost) = try await setupPostConfig(config)
        let uploads = try prepareFiles(files)  // read and checked before the record is created
        var data = data
        if let d = config["data"] { data = d }
        let sentData = data != nil
        var view = config.object ?? JSONObject()
        if let t = conf["table"] { view["table"] = t }
        let enc = try await maybeEncrypt(data ?? .null, view: view, hasData: sentData)
        conf["data"] = nil
        if !enc.omit {
            if !enc.encrypted && DB.jsonBytes(enc.send) > 2 * 1024 * 1024 { throw DB.err("Data should not exceed 2MB", "INVALID_REQUEST") }
            conf["data"] = enc.send
        }
        let ridIn = conf["record_id"]?.string
        if enc.files == "decrypt", let rid = ridIn {
            // private -> not private: attachments back to plaintext while the key is still here
            let retire = try await convertRecordFiles(rid, direction: "decrypt")
            conf["remove_bin"] = .array((conf["remove_bin"]?.array ?? []) + retire.map { .string($0) })
        }
        if let spill = enc.spill, let rid = ridIn {
            // ciphertext over 256 KB travels as a file, uploaded before the record points at it
            let up = try await uploadPrepared([PreparedFile(name: Enc.ctKey, filename: Enc.ctFile, content: spill, contentType: "application/octet-stream")], recordId: rid)
            if let first = up.errors.first { throw first.error }
            if enc_hasDek(rid), let ep = up.binEndpoints.first, !ep.isEmpty {
                self.enc?.deks[rid]?.ctURL = ep
                self.enc?.deks[rid]?.ctStale = []
            }
        }
        if let retire = enc.retire, let _ = ridIn {
            // old payload files: retired whether this write spilled again or now fits inline
            conf["remove_bin"] = .array((conf["remove_bin"]?.array ?? []) + retire.map { .string($0) })
        }
        var rec = try await call("post-record", .object(conf), auth: await signedIn(), method: "POST")
        if enc.encrypted, let r = rec["rec"]?.string, !r.isEmpty { bindRecordDek(r, enc.dek) }
        if enc.files == "encrypt", let r = rec["rec"]?.string, !r.isEmpty {
            // now private with its key cached: seal the existing attachments, then retire the plain ones
            do {
                let retire = try await convertRecordFiles(r, direction: "encrypt")
                if !retire.isEmpty { try await postRecord(config: ["record_id": .string(r), "remove_bin": .array(retire.map { .string($0) })]) }
            } catch {
                warn("Failed to encrypt existing attachments after making the record private: \(error)")
            }
        }
        if !uploads.isEmpty {
            if !enc.encrypted { try await confirmFileDek(rec["rec"]?.string) }
            let result = try await uploadPrepared(uploads, recordId: rec["rec"]?.string ?? "", service: conf["service"]?.string)
            rec["bin"] = .array((rec["bin"]?.array ?? []) + result.binEndpoints.map { .string($0) })
        }
        if let r = isReferencePost, let k = rec["reference_private_key"]?.string { privateAccessKey[r] = k }
        var record = try await normalizeRecord(rec, skipDataFetch: sentData, skipDecrypt: enc.encrypted)
        if sentData, DB.isOffloadMarker(rec["data"]) { record["data"] = data! }
        if enc.encrypted, let plain = enc.plain {
            record["data"] = plain
            record["encrypted"] = ["status": "encrypted", "recipients": .array(enc.recipients.map { .string($0) })]
        }
        rememberUniqueId(scope(conf["service"], conf["owner"]), record)
        _ = isReferencePost
        return record
    }

    /// Many records in few requests: items = [["data": ..., "config": [...]]]. Returns ["list", "failed"].
    public func postRecords(_ items: [JSON]) async throws -> JSON {
        try await ensureConnection()
        if items.isEmpty { throw DB.err("\"items\" should be a non-empty array.") }
        var queue: [(Int, JSONObject, EncResult?)] = []
        var failed: [JSON] = []
        var out: [JSON] = []
        for (i, item) in items.enumerated() {
            do {
                guard let io = item.object else { throw DB.err("\"items[\(i)]\" should be an object with \"config\".") }
                guard let cfg = io["config"], cfg.isObject else { throw DB.err("\"items[\(i)].config\" is required.") }
                var (conf, _) = try await setupPostConfig(cfg)
                let payload = cfg["data"] ?? io["data"]
                let has = payload != nil
                var view = cfg.object!
                if let t = conf["table"] { view["table"] = t }
                let enc = try await maybeEncrypt(payload ?? .null, view: view, hasData: has)
                conf["data"] = nil
                var sealed: EncResult?
                if enc.encrypted {
                    if enc.spill != nil {
                        // skapi-js stores an empty ciphertext here (no payload file is uploaded in bulk); refuse instead
                        throw DB.err("This encrypted update is over 256 KB once sealed; save it with postRecord().", "INVALID_REQUEST")
                    }
                    conf["data"] = enc.send
                    sealed = enc
                } else if has {
                    if DB.jsonBytes(payload!) > 2 * 1024 * 1024 { throw DB.err("Data should not exceed 2MB", "INVALID_REQUEST") }
                    conf["data"] = payload!
                }
                queue.append((i, conf, sealed))
            } catch let e as SkapiError {
                failed.append(["index": .number(Double(i)), "code": .string(e.code.isEmpty ? "INVALID_PARAMETER" : e.code), "message": .string(e.message)])
            }
        }
        var position = 0
        while position < queue.count {
            let chunk = Array(queue[position..<min(position + 100, queue.count)])
            let answered = try await bulkPost(chunk.map { ($0.1, $0.2) })
            if answered.isEmpty {
                for (idx, _, _) in chunk {
                    failed.append(["index": .number(Double(idx)), "code": "ERROR", "message": "The server answered nothing for this record."])
                }
                position += chunk.count
                continue
            }
            let taken = min(answered.count, chunk.count)
            for k in 0..<taken {
                let rec = answered[k]
                if rec["record_id"].truthy { out.append(rec) }
                else {
                    let e = rec["error"]?.object ?? JSONObject()
                    failed.append(["index": .number(Double(chunk[k].0)), "code": e["code"].truthy ? e["code"]! : "ERROR",
                                   "message": e["message"].truthy ? e["message"]! : "The record was not saved."])
                }
            }
            position += taken
        }
        failed.sort { ($0["index"]?.number ?? 0) < ($1["index"]?.number ?? 0) }
        return ["list": .array(out), "failed": .array(failed)]
    }

    private func bulkPost(_ configs: [(JSONObject, EncResult?)]) async throws -> [JSON] {
        let services = Set(configs.compactMap { $0.0["service"]?.pyString })
        let owners = Set(configs.compactMap { $0.0["owner"]?.pyString })
        if services.count > 1 { throw DB.err("All bulk params should share the same \"service\" value.") }
        if owners.count > 1 { throw DB.err("All bulk params should share the same \"owner\" value.") }
        let commonService = services.first ?? "", commonOwner = owners.first ?? ""
        let sent: [JSON] = configs.map { c in
            var o = JSONObject()
            for (k, v) in c.0 where k != "service" && k != "owner" { o[k] = v }
            return .object(o)
        }
        let res = try await call("post-record", ["_is_bulk_": .array(sent), "service": .string(commonService), "owner": .string(commonOwner)],
                                 auth: await signedIn(), method: "POST")
        guard let list = res.array else { return [] }
        var records: [JSON] = []
        for (c, raw) in zip(configs, list) {
            let (conf, sealed) = c
            var rec: JSON = raw.isObject ? try await normalizeRecord(raw, skipDataFetch: conf.contains("data"), skipDecrypt: sealed != nil) : .object(JSONObject())
            if conf.contains("data"), raw.isObject, DB.isOffloadMarker(raw["data"]), !raw["error"].truthy { rec["data"] = conf["data"]! }
            if let s = sealed, let rid = rec["record_id"]?.string, !rid.isEmpty {
                bindRecordDek(rid, s.dek)
                rec["data"] = s.plain ?? .null
                rec["encrypted"] = ["status": "encrypted"]
            }
            if let e = raw["error"], e.truthy, !rec["record_id"].truthy { rec["error"] = e }
            rememberUniqueId(scope(commonService.isEmpty ? nil : .string(commonService), commonOwner.isEmpty ? nil : .string(commonOwner)), rec)
            records.append(rec)
        }
        return records
    }

    // ---- files ------------------------------------------------------------------------------

    struct UploadResult {
        var completed: [String] = []
        var failed: [String] = []
        var errors: [(file: String, name: String, error: SkapiError)] = []
        var binEndpoints: [String] = []
        var landed: [String] = []

        var json: JSON {
            ["completed": .array(completed.map { .string($0) }), "failed": .array(failed.map { .string($0) }),
             "errors": .array(errors.map { ["file": .string($0.file), "name": .string($0.name),
                                            "error": ["code": .string($0.error.code), "message": .string($0.error.message)]] }),
             "bin_endpoints": .array(binEndpoints.map { .string($0) })]
        }
    }

    /// Attaches files to a record you can write. Returns ["completed", "failed", "errors", "bin_endpoints"].
    @discardableResult
    public func uploadFiles(_ files: [UploadFile], recordId: String, service: String? = nil) async throws -> JSON {
        if recordId.isEmpty { throw DB.err("\"record_id\" is required.") }
        let entries = try prepareFiles(files)
        try await confirmFileDek(recordId)  // an encrypted record's files are sealed only with its current key
        return try await uploadPrepared(entries, recordId: recordId, service: service).json
    }

    func uploadPrepared(_ entriesIn: [PreparedFile], recordId: String, service: String? = nil) async throws -> UploadResult {
        var entries: [PreparedFile] = []
        for e in entriesIn { entries.append(try maybeEncryptFile(recordId, e)) }  // sealed when the record's key is cached
        let reservedKey = DB.randomKey(6)
        let svc = service ?? self.service
        let base: JSONObject = ["reserved_key": .string(reservedKey), "service": .string(svc), "request": "post", "id": .string(recordId)]
        let params: [JSONObject] = entries.map {
            ["key": .string("\($0.name)/\($0.filename)"), "sizeKey": .string(DB.toBase62($0.content.count)),
             "contentType": $0.contentType.map { .string($0) } ?? .null]
        }
        var permits = [Any?](repeating: nil, count: entries.count)
        if entries.count >= 5 && !bulkPermitsUnavailable {
            do {
                var start = 0
                while start < entries.count {
                    let chunk = Array(params[start..<min(start + 100, params.count)])
                    let res = try await call("get-signed-urls", ["files": .array(chunk.map { .object($0) }), "reserved_key": .string(reservedKey),
                                                                 "service": .string(svc), "request": "post", "id": .string(recordId)],
                                             auth: await signedIn())
                    let answered = res["list"]?.array ?? []
                    var errs: [Int: JSONObject] = [:]
                    for f in res["failed"]?.array ?? [] { if let o = f.object, let i = o["index"]?.int { errs[i] = o } }
                    for k in 0..<chunk.count {
                        if let e = errs[k] {
                            permits[start + k] = SkapiError(e["message"]?.string ?? "Upload permit refused.", code: e["code"]?.string ?? "ERROR")
                        } else if k < answered.count, answered[k].truthy {
                            permits[start + k] = answered[k]
                        } else {
                            permits[start + k] = SkapiError("No upload permit was answered for this file.", code: "ERROR")
                        }
                    }
                    start += 100
                }
            } catch let err as SkapiError {
                if ["404", "501"].contains(err.code) || Rx.search("missing authentication token|not implemented", err.message, .caseInsensitive)
                    || (err.code == "403" && Rx.search("not found", err.message, .caseInsensitive)) {
                    bulkPermitsUnavailable = true
                    permits = [Any?](repeating: nil, count: entries.count)
                } else {
                    throw err
                }
            }
        }
        var result = UploadResult()
        for (i, e) in entries.enumerated() {
            var permit = permits[i]
            if permit == nil {
                var body = params[i]
                for (k, v) in base { body[k] = v }
                do { permit = try await call("get-signed-url", .object(body), auth: await signedIn()) }
                catch let err as SkapiError { permit = err }
            }
            if let err = permit as? SkapiError {
                result.binEndpoints.append("")
                result.failed.append(e.filename)
                result.errors.append((e.filename, e.name, err))
                continue
            }
            let p = permit as? JSON ?? .null
            let cdn = p["cdn"]?.string ?? ""
            result.binEndpoints.append(cdn)
            do {
                try await requester.upload(url: p["url"]?.string ?? "", fields: p["fields"]?.object ?? JSONObject(), filename: e.filename,
                                           content: e.content, contentType: e.contentType)
                result.completed.append(e.filename)
                result.landed.append(cdn)
            } catch let err as SkapiError {
                result.failed.append(e.filename)
                result.errors.append((e.filename, e.name, err))
            }
        }
        return result
    }

    /// Removes files from records by their urls.
    @discardableResult
    public func deleteFiles(_ endpoints: [String]) async throws -> JSON {
        // A non-public file's url ends in "?t=<token>" and is percent-encoded (getFileEndpoint). The server
        // removes the stored, decoded url by exact string and answers success when nothing matched, so
        // the stored form is sent.
        let list = endpoints.map { JSON.string(storedRecordFileURL($0)) }
        let res = try await call("del-files", ["endpoints": .array(list), "storage": "records"], auth: true, method: "POST")
        if let a = res.array {
            var out: [JSON] = []
            for r in a { out.append(try await normalizeRecord(r)) }
            return .array(out)
        }
        return res
    }

    // ---- reading files ----------------------------------------------------------------------

    enum FileDataType { case bytes, text, endpoint, info }

    enum FileOutput {
        case bytes(Data)
        case text(String)
        case endpoint(String)
        case info(JSON)
    }

    /// A record file's bytes (decrypted when it was sealed on upload).
    /// expires: seconds, to read through a signed URL instead of the signed-in session.
    public func getFile(_ url: String, expires: Double? = nil) async throws -> Data {
        if case .bytes(let d) = try await getFileInternal(url, dataType: .bytes, expires: expires) { return d }
        return Data()
    }

    /// A record file as text (UTF-8).
    public func getFileText(_ url: String, expires: Double? = nil) async throws -> String {
        let d = try await getFile(url, expires: expires)
        return String(decoding: d, as: UTF8.self)
    }

    /// A URL you can open (an image view, a player, a share sheet). With `expires` (seconds) it is a
    /// signed link that works without signing in; otherwise a non-public file's link carries the
    /// user's token and works while the session does.
    public func getFileEndpoint(_ url: String, expires: Double? = nil) async throws -> String {
        if case .endpoint(let s) = try await getFileInternal(url, dataType: .endpoint, expires: expires) { return s }
        return url
    }

    /// What a record file url says (record, uploader, size, access group), without downloading.
    public func getFileInfo(_ url: String) async throws -> JSON {
        if case .info(let j) = try await getFileInternal(url, dataType: .info, expires: nil) { return j }
        return .null
    }

    /// Downloads a record file to a local file. Returns the file's URL.
    @discardableResult
    public func downloadFile(_ url: String, to destination: URL, expires: Double? = nil) async throws -> URL {
        let d = try await getFile(url, expires: expires)
        try d.write(to: destination, options: .atomic)
        return destination
    }

    func getFileInternal(_ urlIn: String, dataType: FileDataType, expires expiresIn: Double?, ref: String? = nil, raw: Bool = false) async throws -> FileOutput {
        let requestedURL = urlIn
        let split = urlIn.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false).map(String.init)
        var base = split[0]
        let query = split.count > 1 ? split[1] : ""
        guard let parts = Check.splitURL(base), parts.scheme == "http" || parts.scheme == "https", !parts.netloc.isEmpty else {
            throw DB.err("\"\(urlIn)\" is an invalid url.")
        }
        base = base.replacingOccurrences(of: " ", with: "%20")
        var url = base + (split.count > 1 ? "?" + query : "")
        let expires = expiresIn ?? 0

        let host = parts.netloc.components(separatedBy: ".")
        let subdomain: String? = (host.count == 3 && host[1] == "skapi") ? host[0] : nil
        var targetKey = Array(base.components(separatedBy: "/").dropFirst(3))
        var needAuth = false
        var isSkapiFile = subdomain != nil
        let presigned = Rx.search("(^|&)(Signature|X-Amz-Signature)=", query)
        if presigned {
            // a link from getFileEndpoint(..., expires:): already signed, opened as it is
            if dataType == .endpoint { return .endpoint(url) }
            targetKey = []
        }
        if subdomain == nil, let first = targetKey.first, first == "auth" || first == "publ" {
            if targetKey.count < 4 || !Check.isUUID(targetKey[2]) || !Check.isUUID(targetKey[3]) { throw DB.err("Invalid file url.") }
            needAuth = first == "auth"
            isSkapiFile = true
        }
        let fileService: String? = subdomain != nil ? nil : (targetKey.count > 1 ? targetKey[1] : nil)

        if dataType == .info {
            rememberHandedOutURL(url, requestedURL)
            let g = targetKey.count > 6 ? targetKey[6] : nil
            var group: JSON = g.map { .string($0) } ?? .null
            if g == "**" { group = "private" } else if g == "01" { group = "authorized" } else if g == "00" { group = "public" }
            else if let gs = g, let n = Int(gs), gs.allSatisfy({ $0.isNumber }) { group = .number(Double(n)) }
            return .info([
                "url": .string(url), "filename": .string(targetKey.last ?? ""), "fileKey": .string(targetKey.count > 1 ? targetKey[targetKey.count - 2] : ""),
                "access_group": group,
                "uploader": targetKey.count > 3 ? .string(targetKey[3]) : .null,
                "record_id": .string(targetKey.count > 5 && targetKey[4] == "records" ? targetKey[5] : "N/A"),
                "filesize": targetKey.count > 9 ? .number(DB.fromBase62(targetKey[9])) : .null,
                "uploaded": targetKey.count > 8 ? .number(DB.fromBase62(targetKey[8])) : .null,
            ])
        }

        if expires != 0 {
            if !isSkapiFile { throw DB.err("Expires option can only be used on skapi cdn endpoints.") }
            if expires < 0 { throw DB.err("\"config.expires\" should be > 0. (seconds)") }
            var params: JSONObject = ["request": .string(subdomain != nil ? "get-host" : "get"),
                                      "id": .string(subdomain ?? (targetKey.count > 5 ? targetKey[5] : "")),
                                      "key": .string(requestedURL.components(separatedBy: "?")[0]), "expires": .number(expires)]
            if let s = fileService { params["service"] = .string(s) }
            url = try await call("get-signed-url", .object(params), auth: true)["url"]?.string ?? url
        } else if needAuth {
            let token = try await freshIdToken()
            url += (url.contains("?") ? "&" : "?") + "t=" + encodeURIComponent(token)
            let group = targetKey.count > 6 ? targetKey[6] : ""
            let u = userObj ?? JSONObject()
            let myGroup = u["access_group"]?.number ?? 0
            if u["user_id"]?.string != targetKey[3] && (group == "**" || (Int(group).map { Double($0) > myGroup } ?? false)) {
                let rid = targetKey.count > 5 ? targetKey[5] : ""
                var key = cachedPrivateKey(rid)
                if key == nil && owner != "skapi" {
                    var p: JSONObject = ["record_id": .string(rid)]
                    if let r = ref { p["reference_id"] = .string(r) }
                    key = try? await requestPrivateRecordAccessKey(.object(p))
                }
                if let k = key { url += "&p=" + encodeURIComponent(k) }
            }
        }

        if dataType == .endpoint {
            // a url handed out here may be fed back to deleteFiles or remove_bin
            rememberHandedOutURL(url, requestedURL)
            return .endpoint(url)
        }
        var content: Data
        if presigned || expires != 0 {
            content = try await requester.fetchPlain(url)
        } else {
            content = try await requester.requestRaw(url, nil, auth: false, method: "GET", token: nil, fetchOptions: nil, ignoreService: true,
                                                     stableGateway: false, contentType: "application/x-www-form-urlencoded", extraHeaders: nil, raw: true).bytes
        }
        if !raw { content = try await maybeDecryptFile(requestedURL, content) }
        if dataType == .text { return .text(String(decoding: content, as: UTF8.self)) }
        return .bytes(content)
    }

    // ---- private record access --------------------------------------------------------------

    private func recordAccess(_ recordId: JSON?, _ uid: JSON?, _ execute: String) async throws -> JSON {
        let ids = try Skapi.recordAccessIds(recordId, uid)
        return try await call("grant-private-access", ["record_id": recordId ?? .null, "user_id": .array(ids.map { .string($0) }),
                                                       "execute": .string(execute)], auth: true, ignoreService: true)
    }

    static func recordAccessIds(_ recordId: JSON?, _ uid: JSON?) throws -> [String] {
        guard recordId?.isString == true else {
            throw DB.err("\(jd(recordId)) is invalid in \"record_id\". allowed type or value is: Type<string>.")
        }
        guard let uid = uid, uid.truthy else { throw DB.err("User ID is required.") }
        let ids = uid.string.map { [JSON.string($0)] } ?? uid.array ?? [uid]
        if ids.count > 100 { throw DB.err("Cannot process more than 100 users at once.") }
        return try ids.map { try DB.userId($0, "User ID in \"user_id\"") }
    }

    /// Lets users read one of your private records: ["record_id", "user_id": id or [ids]].
    @discardableResult
    public func grantPrivateRecordAccess(_ params: JSON) async throws -> JSON {
        let uid = params["user_id"]
        if enc != nil, let u = uid, u.truthy, let rid = params["record_id"]?.string {
            // an encrypted record gets a key wrap for each new user first
            try await encAddRecipients(rid, u.string.map { [$0] } ?? (u.array ?? []).compactMap { $0.string })
        }
        return try await recordAccess(params["record_id"], uid, "add")
    }

    /// Takes back access to one of your private records. With encryption, the record's key is replaced first.
    @discardableResult
    public func removePrivateRecordAccess(_ params: JSON) async throws -> JSON {
        let uid: JSON? = params["user_id"].truthy ? params["user_id"] : nil
        if enc != nil {
            // the data key is rolled BEFORE the access change: the roll is the step that can fail, and
            // failing first leaves access exactly as it was (as skapi-js)
            let ids = try Skapi.recordAccessIds(params["record_id"], uid)
            try await encDropAndRoll(params["record_id"]?.string ?? "", ids)
        }
        return try await recordAccess(params["record_id"], uid, "remove")
    }

    /// Who can read a private record, or which private records a user can read.
    public func listPrivateRecordAccess(_ params: JSON, fetchOptions: FetchOptions? = nil) async throws -> JSON {
        let rid: JSON? = params["record_id"].truthy ? params["record_id"] : nil
        let uid: JSON? = params["user_id"].truthy ? params["user_id"] : nil
        if rid == nil && uid == nil { throw DB.err("Either record_id or user_id must be provided.") }
        var p = JSONObject()
        if let r = rid { p["record_id"] = r }
        if let u = uid {
            if u.isString { p["user_id"] = .array([.string(try DB.userId(u))]) }
            else if let a = u.array { p["user_id"] = .array(try a.map { .string(try DB.userId($0)) }) }
            else { throw DB.err("user_id should be type: <string | string[]>") }
        }
        p["execute"] = "list"
        var res = try await call("grant-private-access", .object(p), auth: true, fetchOptions: fetchOptions?.object, ignoreService: true)
        if let list = res["list"]?.array {
            res["list"] = .array(list.map { itemJSON in
                guard var item = itemJSON.object else { return itemJSON }
                if let ru = item["rec_usr"]?.string, !ru.isEmpty {
                    let s = ru.components(separatedBy: "/")
                    item["record_id"] = .string(s[0]); item["user_id"] = .string(s.count > 1 ? s[1] : "")
                } else if let ur = item["usr_rec"]?.string, !ur.isEmpty {
                    let s = ur.components(separatedBy: "/")
                    item["user_id"] = .string(s[0]); item["record_id"] = .string(s.count > 1 ? s[1] : "")
                }
                return .object(item)
            })
        }
        return res
    }

    /// The cached private access key for a record, or nil when there is none worth sending. The
    /// server mints "<exp>.<hash>"; a key that expires within a minute, or a legacy key, is dropped.
    func cachedPrivateKey(_ recordId: String) -> String? {
        guard let key = privateAccessKey[recordId], !key.isEmpty else { return nil }
        if let g = Rx.groups("^([0-9]+)\\.", key), let exp = Double(g[1]), exp - DB.privateKeyRefreshMargin > Date().timeIntervalSince1970 {
            return key
        }
        privateAccessKey[recordId] = nil
        return nil
    }

    /// A key that opens a private record you were granted (cached until shortly before it expires).
    public func requestPrivateRecordAccessKey(_ params: JSON) async throws -> String {
        let rid = params["record_id"], ref = params["reference_id"]
        guard let r = rid, r.truthy else { throw DB.err("Record ID is required.") }
        guard let ridS = r.string else { throw DB.err("Record ID should be type: <string | string[]>") }
        if let f = ref, f.truthy, !f.isString { throw DB.err("Reference ID should be type: <string>") }
        if let k = cachedPrivateKey(ridS) { return k }
        var body: JSONObject = ["record_id": .string(ridS)]
        if let f = ref, f.truthy { body["reference_id"] = f }
        let res = try await call("request-private-access-key", .object(body), auth: true)
        guard let key = res.string ?? res["private_key"]?.string else { throw SkapiError("Invalid private access key response.", code: "ERROR") }
        privateAccessKey[ridS] = key
        return key
    }

    // ---- decoding -----------------------------------------------------------------------------

    func normalizeRecord(_ recordJSON: JSON, skipDataFetch: Bool = false, skipBinResolve: Bool = false, skipDecrypt: Bool = false) async throws -> JSON {
        guard let record = recordJSON.object else { return recordJSON }
        if record["record_id"].truthy { return recordJSON }
        var out: JSONObject = [
            "user_id": "", "record_id": "", "updated": 0, "uploaded": 0, "readonly": false,
            "table": ["name": "", "access_group": 0, "subscription": ["is_subscription_record": false, "upload_to_feed": false,
                                                                      "notify_subscribers": false, "feed_referencing_records": false,
                                                                      "notify_referencing_records": false]],
            "referenced_count": 0,
            "source": ["referencing_limit": nil, "prevent_multiple_referencing": false, "can_remove_referencing_records": false,
                       "only_granted_can_reference": false],
            "ip": "", "bin": .object(JSONObject()),
        ]
        var table = out["table"]!.object!
        var subscription = table["subscription"]!.object!
        var source = out["source"]!.object!
        var anonymous = false
        let bins = record["bin"]?.array ?? []
        var dataURL: String?
        var ctURLs: [String] = []
        for u in bins {
            if let s = u.string {
                let sp = Array(s.components(separatedBy: "/").dropFirst(3))
                if sp.count >= 12 && sp[10] == "__data__" && sp.last == "__json__.json" { dataURL = s }
                if sp.count >= 12 && sp[10] == Enc.ctKey && sp.last == Enc.ctFile { ctURLs.append(s) }  // an encrypted record's large ciphertext
            }
        }
        // newest upload first: every record file url carries its upload time right after "bin"
        func uploaded(_ u: String) -> Double {
            let sp = Array(u.components(separatedBy: "/").dropFirst(3))
            return sp.count > 8 && sp[7] == "bin" ? DB.fromBase62(sp[8]) : 0
        }
        ctURLs.sort { uploaded($0) > uploaded($1) }
        let ctURL = ctURLs.first

        if let ipv = record["ip"] {
            let parts = ipv.pyString.components(separatedBy: "#")
            var ip = parts[0]
            if parts.count > 1 { out["unique_id"] = .string(parts.dropFirst().joined(separator: "#")) }
            if ip.hasSuffix("R") {
                out["readonly"] = true
                ip.removeLast()
            }
            if Rx.match("^\\d{1,3}-\\d{1,3}-\\d{1,3}-\\d{1,3}$", ip) {
                ip = ip.replacingOccurrences(of: "-", with: ".")
                anonymous = true
            }
            out["ip"] = .string(ip)
        }
        if let rec = record["rec"]?.string, !rec.isEmpty {
            out["record_id"] = .string(rec)
            out["uploaded"] = .number(DB.fromBase62(String(rec.dropLast(9))))
        }
        if let u = record["usr"] { out["user_id"] = u }
        if let tbl = record["tbl"], table["name"] == .string("") {
            let p = tbl.pyString.components(separatedBy: "/")
            table["name"] = .string(DB.decodeDelimiters(p[0]))
            table["access_group"] = p.count > 2 ? DB.accessGroupOut(p[2]) : 0
            subscription["is_subscription_record"] = .bool(p.count > 3 && !p[3].isEmpty)
        }
        if let ut = record["usr_tbl"] {
            let p = ut.pyString.components(separatedBy: "/")
            if !out["user_id"].truthy { out["user_id"] = .string(p[0]) }
            if table["name"] == .string("") {
                table["name"] = .string(DB.decodeDelimiters(p.count > 1 ? p[1] : ""))
                table["access_group"] = p.count > 3 ? DB.accessGroupOut(p[3]) : 0
                subscription["is_subscription_record"] = .bool(p.count > 4 && !p[4].isEmpty)
            }
        }
        if let idx = record["idx"]?.string {
            let parts = idx.components(separatedBy: "!")
            out["index"] = ["name": .string(DB.decodeDelimiters(parts[0])), "value": try DB.typedString("!" + parts.dropFirst().joined(separator: "!"))]
        }
        if let ref = record["ref"], ref.truthy { out["reference"] = .string(ref.pyString.components(separatedBy: "/")[0]) }
        if let tags = record["tags"] {
            out["tags"] = tags.array.map { .array($0.map { DB.decodeDelimiters($0) }) } ?? tags
        }
        if let upd = record["upd"] { out["updated"] = upd }
        if let a = record["acpt_mrf"] { source["prevent_multiple_referencing"] = .bool(!a.truthy) }
        if let l = record["ref_limt"] { source["referencing_limit"] = l }
        if let r = record["rfd"] { out["referenced_count"] = r }
        var bin = JSONObject()
        for u in bins {
            guard let s = u.string, !s.isEmpty else { continue }
            let path = s.components(separatedBy: "/").dropFirst(3).joined(separator: "/")
            let sp = path.components(separatedBy: "/")
            if sp.count < 12 || sp[10] == "__data__" || sp[10] == Enc.ctKey { continue }
            var pathKey = sp[10]
            let group = DB.accessGroupOut(sp[6])
            var endpoint = s
            if group != .string("public") && !skipBinResolve {
                if case .endpoint(let e)? = try? await getFileInternal(s, dataType: .endpoint, expires: nil, ref: out["reference"]?.string) { endpoint = e }
            }
            var entry: JSONObject = ["access_group": group, "filename": .string(sp.last!), "url": .string(endpoint), "path": .string(path),
                                     "size": .number(DB.fromBase62(sp[9])), "uploaded": .number(DB.fromBase62(sp[8]))]
            if let sealed = Enc.parseFileMarker(pathKey) {
                // an encrypted attachment: listed under its own field name, with the plaintext size
                pathKey = sealed.0
                entry["size"] = .number(Double(sealed.1))
                entry["encrypted"] = true
                entry["stored_size"] = .number(DB.fromBase62(sp[9]))
            }
            bin[pathKey] = .array((bin[pathKey]?.array ?? []) + [.object(entry)])
        }
        out["bin"] = .object(bin)
        if let prv = record["prv_acs"]?.object {
            for (k, v) in prv {
                if ["notify_subscribers", "upload_to_feed", "feed_referencing_records", "notify_referencing_records"].contains(k) {
                    subscription[k] = v
                } else if k == "referencing_index_restrictions", let list = v.array {
                    source[k] = .array(list.map { i in
                        guard var io = i.object, let n = io["name"]?.string else { return i }
                        io["name"] = .string(DB.decodeDelimiters(n))
                        return .object(io)
                    })
                } else {
                    source[k] = v
                }
            }
        }
        table["subscription"] = .object(subscription)
        out["table"] = .object(table)
        out["source"] = .object(source)
        if let r = record["data"] {
            let (decoded, changed) = DB.parseStoredData(r)
            if changed {
                out["data"] = decoded
            } else if DB.isOffloadMarker(r) {
                if dataURL != nil && skipDataFetch {
                    out["data"] = r
                } else if dataURL != nil || !skipDataFetch {
                    let url = dataURL ?? derivedDataURL(record, r["__data__"]?.string ?? "", bins)
                    out["data"] = r
                    if let u = url {
                        do {
                            let text = try await getFileInternal(u, dataType: .text, expires: nil, ref: out["reference"]?.string)
                            if case .text(let t) = text { out["data"] = try JSON.parse(t) }
                        } catch {
                            out["data"] = dataURL != nil ? .null : r
                            if enc != nil { out["encrypted"] = ["status": "failed", "reason": "DATA_UNAVAILABLE"] }
                        }
                    }
                } else {
                    out["data"] = r
                }
            } else {
                out["data"] = r
            }
            if !skipDecrypt, let d = out["data"] {
                let ctx = DecryptContext(accessGroup: table["access_group"] ?? .null, tableName: table["name"]?.string ?? "",
                                         userId: out["user_id"]?.string ?? "", recordId: out["record_id"]?.string ?? "",
                                         uniqueId: out["unique_id"]?.string, ctURL: ctURL, ctURLs: ctURLs)
                let (value, flag) = await maybeDecrypt(d, ctx)
                if let f = flag {
                    out["data"] = value
                    out["encrypted"] = f
                }
            }
        }
        if anonymous { out["user_id"] = .string("anonymous:" + (out["user_id"]?.pyString ?? "")) }
        return .object(out)
    }

    /// The offloaded data file's URL when the record's file list does not carry it.
    private func derivedDataURL(_ record: JSONObject, _ markerPath: String, _ bins: [JSON]) -> String? {
        if !Rx.match("^[0-9A-Za-z]+/[0-9A-Za-z]+/__data__/__json__\\.json$", markerPath) { return nil }
        var svc: String?, own: String?, uploader: String?, group: String?
        if let s = record["srvc"]?.string {
            let first = s.components(separatedBy: "!")[0]
            let parts = first.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false).map(String.init)
            svc = parts[0]
            own = parts.count > 1 ? parts[1] : ""
        }
        if let ut = record["usr_tbl"]?.string {
            let p = ut.components(separatedBy: "/")
            uploader = p[0]
            if svc == nil || svc!.isEmpty { svc = p.count > 2 ? p[2] : nil }
            group = p.count > 3 ? p[3] : nil
        } else if let t = record["tbl"]?.string {
            let p = t.components(separatedBy: "/")
            if svc == nil || svc!.isEmpty { svc = p.count > 1 ? p[1] : nil }
            group = p.count > 2 ? p[2] : nil
        }
        if let u = record["usr"]?.string, !u.isEmpty { uploader = u }
        if (own == nil || own!.isEmpty) && svc == self.service { own = self.owner }
        var origin: String?
        for b in bins {
            if let s = b.string, let sv = svc, !sv.isEmpty, s.contains("/\(sv)/"), let parts = Check.splitURL(s) {
                origin = "\(parts.scheme)://\(parts.netloc)"
                break
            }
        }
        let rec = record["rec"]?.string
        func idOK(_ x: String?) -> Bool { x.map { !$0.isEmpty && Rx.match("^[0-9A-Za-z_-]+$", $0) } ?? false }
        guard let o = origin, idOK(svc), idOK(own), idOK(uploader), idOK(rec), let g = group, Rx.match("^(\\d{2}|\\*\\*)$", g) else { return nil }
        return "\(o)/\(g == "00" ? "publ" : "auth")/\(svc!)/\(own!)/\(uploader!)/records/\(rec!)/\(g)/bin/\(markerPath)"
    }
}

/// A warning the SDK prints instead of failing a call (as Python's warnings.warn).
func warn(_ message: String) {
    #if DEBUG
    print("skapi: \(message)")
    #endif
}
