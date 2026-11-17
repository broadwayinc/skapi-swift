import Foundation

/// Client-side record encryption, ported from skapi-py (_encryption.py) and skapi-js
/// (src/methods/encryption.ts). See `EncryptionOptions`.
extension Skapi {
    // ---- strings ---------------------------------------------------------------------------------

    func eS(_ kind: String, _ user: String) -> String { "\(Enc.v)|\(kind)|\(service)|\(owner)|\(user)" }

    func payloadAAD(_ own: String, _ anch: String, _ anchor: String) -> Data {
        utf8(JSON.array([.string(Enc.v), .string(service), .string(owner), .string(own), .string(anch), .string(anchor)]).jsonString)
    }

    func recipientAAD(_ payloadAAD: Data, _ recipient: String, _ bind: String) -> Data {
        payloadAAD + Data([0]) + utf8(recipient) + Data([0]) + utf8(bind)
    }

    func wrapInfo(_ anchor: String, _ own: String, _ recipient: String, _ fpr: String) -> String {
        "\(Enc.v)|dekwrap|\(service)|\(owner)|\(anchor)|\(own)|\(recipient)|\(fpr)"
    }

    static func anchorOf(_ anch: String?, uid: String?, rid: String?) -> String {
        anch == "uid" ? (uid ?? "") : anch == "rid" ? (rid ?? "") : ""
    }

    func enc_hasDek(_ rid: String) -> Bool { enc?.deks[rid] != nil }

    // ---- keyring -----------------------------------------------------------------------------------

    func findKeyring(_ uid: String) async throws -> JSONObject? {
        guard let s = enc else { return nil }
        let res = try await getRecords(["table": ["name": .string(s.cfg.table), "access_group": "private"],
                                        "index": ["name": "$user_id", "value": .string(uid), "condition": "="]], fetchOptions: ["limit": 2])
        let rows = (res["list"]?.array ?? []).compactMap { $0.object }.filter { $0["user_id"]?.string == uid }
            .sorted { ($0["uploaded"]?.number ?? 0) < ($1["uploaded"]?.number ?? 0) }
        return rows.first
    }

    func passwordWrap(_ mk: Data, _ password: String, _ uid: String) throws -> JSON {
        let it = enc!.cfg.iterations
        let salt = Prim.randomBytes(16)
        let s = B64.url(salt)
        let kek = Enc.passwordKek(password, salt: salt, iterations: it, info: eS("kek", uid))
        var w: JSONObject = ["id": .string(B64.url(Prim.randomBytes(6))), "p": "password", "kdf": ["a": "PBKDF2-SHA256", "it": .number(Double(it)), "s": .string(s)]]
        for (k, v) in try Enc.seal(kek, mk, utf8("\(eS("mk", uid))|PBKDF2-SHA256|\(it)|\(s)")) { w[k] = v }
        w["created"] = .number(nowMs())
        return .object(w)
    }

    func recoveryWrap(_ mk: Data, _ uid: String) throws -> (JSON, String) {
        let raw = Prim.randomBytes(16)
        let salt = Prim.randomBytes(16)
        let s = B64.url(salt)
        let rk = Enc.hkdf(raw, salt: salt, info: eS("recovery", uid))
        var w: JSONObject = ["id": .string(B64.url(Prim.randomBytes(6))), "p": "recovery", "kdf": ["a": "HKDF-SHA256", "s": .string(s)]]
        for (k, v) in try Enc.seal(rk, mk, utf8("\(eS("rk", uid))|HKDF-SHA256|\(s)")) { w[k] = v }
        w["created"] = .number(nowMs())
        return (.object(w), Enc.encodeRecoveryCode(raw))
    }

    func openWithPassword(_ data: JSONObject, _ password: String, _ uid: String) throws -> Data? {
        let wraps = (data["wraps"]?.array ?? []).compactMap { $0.object }.filter { $0["p"] == .string("password") }
            .sorted { ($0["created"]?.number ?? 0) > ($1["created"]?.number ?? 0) }
        if wraps.isEmpty { throw Enc.err("The keyring has no password wrap.", "ENCRYPTION_KEYRING_CORRUPT") }
        for w in wraps {
            guard let kdf = w["kdf"]?.object, let s = kdf["s"]?.string, let it = kdf["it"]?.number else { continue }
            guard let salt = try? B64.urlDecode(s), let iv = try? B64.urlDecode(w["iv"]?.string), let ct = try? B64.urlDecode(w["ct"]?.string) else { continue }
            let kek = Enc.passwordKek(password, salt: salt, iterations: Int(it), info: eS("kek", uid))
            if let mk = try? Enc.open(kek, iv, ct, utf8("\(eS("mk", uid))|PBKDF2-SHA256|\(JSONWriter.jsNumber(it))|\(s)")) { return mk }
        }
        return nil
    }

    func adoptKeyring(_ keyring: JSONObject, _ mk: Data, _ uid: String) async throws {
        guard let s = enc else { return }
        let data = keyring["data"]?.object ?? JSONObject()
        let ik = data["ik"]?.object ?? JSONObject()
        let pkcs8 = try Enc.open(mk, B64.urlDecode(ik["iv"]?.string), B64.urlDecode(ik["ct"]?.string), utf8(eS("ik", uid)))
        var pins: [String: String] = [:]
        if let p = data["pins"]?.object, p["ct"].truthy,
           let iv = try? B64.urlDecode(p["iv"]?.string), let ct = try? B64.urlDecode(p["ct"]?.string),
           let plain = try? Enc.open(mk, iv, ct, utf8("\(Enc.v)|pins|\(service)/\(owner)|\(uid)")),
           let parsed = (try? JSON.parse(utf8Decode(plain)))?.object {
            for (k, v) in parsed { if let f = v.string { pins[k] = f } }
        }
        s.mk = mk
        s.ikPriv = try Prim.loadPKCS8(pkcs8)
        s.pubRaw = try B64.urlDecode(data["pub"]?.string)
        s.fpr = data["fpr"]?.string ?? ""
        s.keyringRecordId = keyring["record_id"]?.string ?? ""
        s.userId = uid
        s.pins = pins
        s.status = "unlocked"
        s.reason = ""
        do { try await repairPublicKey(uid) }
        catch { warn("encryption: the public key directory could not be checked: \(error)") }  // best effort: it never fails the unlock
    }

    /// Puts this keyring's public key back on top of the public key directory when a stray row is
    /// there instead (two devices enrolling at once could leave one). As skapi-js repairPublicKey.
    func repairPublicKey(_ uid: String) async throws {
        guard let s = enc, !uid.isEmpty, let pubRaw = s.pubRaw, let ikPriv = s.ikPriv else { return }
        let res = try await getRecords(["table": ["name": .string(s.cfg.table), "access_group": "authorized"],
                                        "index": ["name": "$user_id", "value": .string(uid), "condition": "="]], fetchOptions: ["limit": 10])
        let rows = (res["list"]?.array ?? []).compactMap { $0.object }
            .filter { $0["user_id"]?.string == uid && $0["data"]?["pub"].truthy == true }
            .sorted { ($0["uploaded"]?.number ?? 0) > ($1["uploaded"]?.number ?? 0) }
        if rows.isEmpty { return }
        let mine = Enc.fingerprint(pubRaw)
        func fprOf(_ r: JSONObject) -> String {
            (try? B64.urlDecode(r["data"]?["pub"]?.string)).map { Enc.fingerprint($0) } ?? ""
        }
        if fprOf(rows[0]) == mine { return }
        // the key about to be published must open what is sealed to it with this session's private key
        let probe = Prim.randomBytes(32)
        let label = "\(Enc.v)|pubcheck|\(uid)"
        let holds: Bool
        if let w = try? Enc.ecdhWrap(probe, peerPub: pubRaw, info: label, aad: utf8(label)),
           let back = try? Enc.ecdhUnwrap(ikPriv, w, info: label, aad: utf8(label)) {
            holds = back == probe
        } else {
            holds = false
        }
        if !holds { return }
        let stray = rows.filter { fprOf($0) != mine }.compactMap { $0["record_id"]?.string }.filter { !$0.isEmpty }
        if s.userId != uid || me != uid { return }  // a lock, logout or another user's login since the unlock
        try await postRecord(["v": 1, "alg": "ECDH-P-256", "user_id": .string(uid), "pub": .string(B64.url(pubRaw)), "fpr": .string(mine),
                              "created": .number(nowMs())],
                             config: ["table": ["name": .string(s.cfg.table), "access_group": "authorized"],
                                      "index": ["name": "pubkey", "value": .string(uid)]])
        if !stray.isEmpty && s.userId == uid && me == uid {
            try await deleteRecords(["record_id": .array(stray.map { .string($0) })])
        }
    }

    func unlockKeyring(_ keyring: JSONObject, _ password: String, _ uid: String) async throws {
        let data = keyring["data"]?.object ?? JSONObject()
        if keyring["user_id"]?.string != uid || (data["user_id"].truthy && data["user_id"]?.string != uid) {
            throw Enc.err("The encryption keyring does not belong to this user.", "ENCRYPTION_KEYRING_CORRUPT")
        }
        guard let mk = try openWithPassword(data, password, uid) else {
            throw Enc.err("Incorrect password: the encryption keyring could not be opened.", "ENCRYPTION_BAD_PASSWORD")
        }
        try await adoptKeyring(keyring, mk, uid)
    }

    func provisionKeyring(_ password: String, _ uid: String) async throws {
        guard let s = enc else { return }
        let mk = Prim.randomBytes(32)
        let (_, pub, pkcs8) = Prim.newIdentity()
        let fpr = Enc.fingerprint(pub)
        var wraps: [JSON] = [try passwordWrap(mk, password, uid)]
        var code: String?
        if s.cfg.recovery == .code {
            let (w, c) = try recoveryWrap(mk, uid)
            wraps.append(w)
            code = c
        }
        let now = nowMs()
        let data: JSON = [
            "v": 1, "alg": "ECDH-P-256", "user_id": .string(uid), "wraps": .array(wraps),
            "ik": .object(try Enc.seal(mk, pkcs8, utf8(eS("ik", uid)))), "self": .object(try Enc.seal(mk, mk, utf8(eS("self", uid)))),
            "pub": .string(B64.url(pub)), "fpr": .string(fpr), "pins": nil, "created": .number(now), "updated": .number(now),
        ]
        let table = s.cfg.table
        let pubRec = try await postRecord(["v": 1, "alg": "ECDH-P-256", "user_id": .string(uid), "pub": .string(B64.url(pub)), "fpr": .string(fpr),
                                           "created": .number(now)],
                                          config: ["table": ["name": .string(table), "access_group": "authorized"],
                                                   "index": ["name": "pubkey", "value": .string(uid)]])
        let rec = try await postRecord(data, config: ["table": ["name": .string(table), "access_group": "private"]])
        if let oldest = try await findKeyring(uid), oldest["record_id"] != rec["record_id"] {
            // another device enrolled first: its keyring wins, and this device's public key and keyring go (best effort)
            let ids = [pubRec["record_id"]?.string, rec["record_id"]?.string].compactMap { $0 }.filter { !$0.isEmpty }
            do { try await deleteRecords(["record_id": .array(ids.map { .string($0) })]) }
            catch { warn("encryption: this device's unused public key and keyring could not be removed: \(error)") }
            try await unlockKeyring(oldest, password, uid)
            return
        }
        var adopted = rec.object ?? JSONObject()
        adopted["data"] = data
        try await adoptKeyring(adopted, mk, uid)
        s.pendingRecoveryCode = code
        s.pendingRecoveryUser = uid
        s.pins = [:]
    }

    /// Open the keyring with the password, or create it when there is none. Creating is for login
    /// only, where the password was just proven; unlockEncryption passes create: false.
    func ensureKeyring(_ password: String, create: Bool = true) async throws {
        guard let s = enc, let u = userObj else { return }
        if u["is_openid"].truthy {
            s.status = "locked"
            s.reason = "OPENID_UNSUPPORTED"
            return
        }
        let uid = me
        let gen = s.gen
        if let keyring = try await findKeyring(uid) {
            try await unlockKeyring(keyring, password, uid)
        } else if !create {
            throw Enc.err("Encryption has not been set up for this account yet. It is set up at the first login with the password: " +
                          "log in with the password to start using it.", "NOT_EXISTS")
        } else {
            try await provisionKeyring(password, uid)
        }
        if s.cfg.persistDevice && s.gen == gen { saveDevice() }
    }

    /// Called after every password sign-in. Never fails the login.
    func encAfterLogin(_ password: String?) async {
        guard let s = enc, let p = password, !p.isEmpty else { return }
        s.clear()  // a previous user's keys never carry over
        do { try await ensureKeyring(p) }
        catch { warn("encryption could not be unlocked at login: \(error)") }
    }

    func encClear(deleteDevice: Bool) {
        guard let s = enc else { return }
        if deleteDevice { self.deleteDevice() }
        s.clear()
    }

    /// true when the keyring got a wrap under the new password (to prune after the change).
    func encRewrapPassword(current: String, new: String) async throws -> Bool {
        guard let s = enc else { return false }
        guard s.status == "unlocked", s.mk != nil else {
            throw Enc.err("Encryption must be unlocked before changing the password, or the encryption keyring would be left " +
                          "wrapped under a password that no longer exists. Call unlockEncryption(password:) first.", "ENCRYPTION_LOCKED")
        }
        let res = try await getRecords(["record_id": .string(s.keyringRecordId)], fetchOptions: ["limit": 1])
        guard let keyring = res["list"]?[0]?.object else {
            throw Enc.err("The encryption keyring could not be read, so the password change was stopped before it could strand it.", "ENCRYPTION_KEYRING_CORRUPT")
        }
        let uid = me
        var data = keyring["data"]?.object ?? JSONObject()
        guard let mk = try openWithPassword(data, current, uid) else {
            throw Enc.err("Incorrect current password: the encryption keyring was not re-wrapped.", "ENCRYPTION_BAD_PASSWORD")
        }
        data["wraps"] = .array((data["wraps"]?.array ?? []) + [try passwordWrap(mk, new, uid)])
        data["updated"] = .number(nowMs())
        try await postRecord(.object(data), config: ["record_id": .string(s.keyringRecordId)])
        return true
    }

    func encPruneWraps() async {
        guard let s = enc, s.status == "unlocked" else { return }
        do {
            let res = try await getRecords(["record_id": .string(s.keyringRecordId)], fetchOptions: ["limit": 1])
            guard var data = res["list"]?[0]?["data"]?.object else { return }
            let all = data["wraps"]?.array ?? []
            let pw = all.filter { $0["p"] == .string("password") }.sorted { ($0["created"]?.number ?? 0) > ($1["created"]?.number ?? 0) }
            if pw.count > 1 {
                data["wraps"] = .array([pw[0]] + all.filter { $0["p"] != .string("password") })
                data["updated"] = .number(nowMs())
                try await postRecord(.object(data), config: ["record_id": .string(s.keyringRecordId)])
            }
        } catch {
            warn("encryption: old password wrap not pruned: \(error)")
        }
    }

    // ---- remember this device ---------------------------------------------------------------------

    private func deviceEntryKey(_ uid: String) -> String { "\(service)/\(owner)#\(uid)" }

    func saveDevice() {
        guard let s = enc, let store = deviceKeyStorage, let mk = s.mk, !s.userId.isEmpty else { return }
        let value: JSON = ["mk": .string(B64.url(mk)), "keyringRecordId": .string(s.keyringRecordId), "saved": .number(nowMs())]
        store.setItem(deviceEntryKey(s.userId), value.jsonString)
    }

    func deleteDevice() {
        guard let s = enc, let store = deviceKeyStorage else { return }
        for uid in Set([s.userId, me]) where !uid.isEmpty { store.removeItem(deviceEntryKey(uid)) }
    }

    /// After a session is restored at launch: unlock from the device store, so a restored session
    /// needs no password (as skapi-js startDeviceUnlock).
    func startDeviceUnlockIfNeeded() {
        guard let s = enc, s.status != "unlocked", s.ready == nil, deviceKeyStorage != nil, !me.isEmpty else { return }
        s.ready = Task { await self.unlockFromDevice() }
    }

    func unlockFromDevice() async {
        guard let s = enc, let store = deviceKeyStorage, s.cfg.persistDevice else { return }
        let uid = me
        if uid.isEmpty { return }
        let gen = s.gen
        guard let text = store.getItem(deviceEntryKey(uid)), let entry = try? JSON.parse(text),
              let mk = try? B64.urlDecode(entry["mk"]?.string) else { return }
        do {
            guard let keyring = try await findKeyring(uid) else {
                store.removeItem(deviceEntryKey(uid))
                return
            }
            if s.gen != gen || me != uid { return }
            try await adoptKeyring(keyring, mk, uid)
        } catch {
            // a stale device entry (password changed elsewhere, keyring rotated) degrades to locked
            if s.gen == gen {
                s.status = "locked"
                s.reason = "NO_SESSION_KEY"
            }
        }
    }

    /// Waits for an unlock from the device store that is still running.
    func awaitEncReady() async {
        if let t = enc?.ready { await t.value }
    }

    // ---- peers ------------------------------------------------------------------------------------

    func peerKeys(_ ids: [String]) async throws -> [String: (Data, String)] {
        guard let s = enc else { return [:] }
        var out: [String: (Data, String)] = [:]
        var pinnedNew = false
        for uid in ids {
            if let k = s.peerPub[uid] { out[uid] = k; continue }
            let res = try await getRecords(["table": ["name": .string(s.cfg.table), "access_group": "authorized"],
                                            "index": ["name": "$user_id", "value": .string(uid), "condition": "="]], fetchOptions: ["limit": 10])
            let rows = (res["list"]?.array ?? []).filter { $0["user_id"]?.string == uid && $0["data"]?["pub"].truthy == true }
                .sorted { ($0["uploaded"]?.number ?? 0) > ($1["uploaded"]?.number ?? 0) }
            guard let top = rows.first else { continue }
            let pub = try B64.urlDecode(top["data"]?["pub"]?.string)
            let fpr = Enc.fingerprint(pub)
            if let pinned = s.pins[uid], pinned != fpr {
                throw Enc.err("The public key for user \"\(uid)\" has changed since it was first seen. " +
                              "This is expected if they reset their account, and is what a key substitution attack also looks like. " +
                              "Verify the new fingerprint out of band, then call pinPeerKey(userId:fingerprint:).", "ENCRYPTION_PEER_KEY_CHANGED")
            }
            if s.pins[uid] == nil {
                if s.cfg.trustPolicy == .strict {
                    throw Enc.err("No pinned key for user \"\(uid)\" and trustPolicy is \"strict\". Pin it first with pinPeerKey().", "ENCRYPTION_PEER_NOT_PINNED")
                }
                s.pins[uid] = fpr
                pinnedNew = true
            }
            s.peerPub[uid] = (pub, fpr)
            out[uid] = (pub, fpr)
        }
        if pinnedNew { try? await persistPins() }
        return out
    }

    func persistPins() async throws {
        guard let s = enc, let mk = s.mk, !s.keyringRecordId.isEmpty else { return }
        let res = try await getRecords(["record_id": .string(s.keyringRecordId)], fetchOptions: ["limit": 1])
        guard var data = res["list"]?[0]?["data"]?.object else { return }
        var pins = JSONObject()
        for (k, v) in s.pins { pins[k] = .string(v) }
        data["pins"] = .object(try Enc.seal(mk, utf8(JSON.object(pins).jsonString), utf8("\(Enc.v)|pins|\(service)/\(owner)|\(s.userId)")))
        data["updated"] = .number(nowMs())
        try await postRecord(.object(data), config: ["record_id": .string(s.keyringRecordId)])
    }

    // ---- write ---------------------------------------------------------------------------------------

    private static func normGroup(_ g: JSON?) -> JSON {
        if let s = g?.string {
            if ["private", "*", "**"].contains(s) { return "private" }
            return ["public": 0, "authorized": 1, "admin": 99][s].map { .number(Double($0)) } ?? 0
        }
        if let n = g?.number { return .number(n) }
        return 0
    }

    /// (access group the write lands on, table name, the record if it had to be read).
    func writeGroup(_ view: JSONObject, hasData: Bool) async throws -> (JSON, String?, JSONObject?) {
        let table = view["table"]
        let name = table?.string ?? table?["name"]?.string
        if table?.isString == true { return (0, name, nil) }
        if let t = table?.object, t.contains("access_group") { return (Skapi.normGroup(t["access_group"]), name, nil) }
        guard let rid = view["record_id"]?.string, !rid.isEmpty else { return (0, name, nil) }
        // the cached data key is trusted only for a write with no data (as skapi-js resolveWriteGroup)
        if let e = enc?.deks[rid], !hasData { return (e.accessGroup, name, nil) }
        guard let current = try await readOwnRecord(rid) else { throw Enc.err("Record \"\(rid)\" not found.", "NOT_EXISTS") }
        return (current["table"]?["access_group"] ?? 0, current["table"]?["name"]?.string, current)
    }

    func readOwnRecord(_ rid: String) async throws -> JSONObject? {
        let q: JSON = Rx.match("^[a-zA-Z0-9]+$", rid) ? ["record_id": .string(rid)] : ["unique_id": .string(rid)]
        let res = try await getRecords(q, fetchOptions: ["limit": 1])
        return res["list"]?[0]?.object
    }

    func ownerCheck(_ current: JSONObject?, _ rid: String, _ what: String) throws {
        if let c = current, c["encrypted"].truthy, c["user_id"]?.string != me {
            throw Enc.err("Record \"\(rid)\" belongs to another user (\(c["user_id"]?.pyString ?? "")), so \(what) would either seal it " +
                          "under the wrong key or strand its contents. Encryption only operates on records you own, " +
                          "no matter what access level you hold.", "ENCRYPTION_NOT_RECORD_OWNER")
        }
    }

    private static func hasBin(_ rec: JSONObject?, encrypted: Bool) -> Bool {
        guard let bin = rec?["bin"]?.object else { return false }
        return bin.values.contains { ($0.array ?? []).contains { ($0["encrypted"]?.truthy ?? false) == encrypted } }
    }

    func maybeEncrypt(_ valueIn: JSON, view: JSONObject, hasData hasDataIn: Bool) async throws -> EncResult {
        var value = valueIn, hasData = hasDataIn
        guard let s = enc else { return EncResult(send: value, omit: !hasData) }
        let rawId = view["record_id"]?.string ?? ""
        if !rawId.isEmpty, let pass = s.passthrough.removeValue(forKey: rawId) { return EncResult(send: pass, encrypted: true) }
        let (group, tableName, record) = try await writeGroup(view, hasData: hasData)
        if group != .string("private") {
            var files: String?
            var current = record
            if !rawId.isEmpty && current == nil { current = try? await readOwnRecord(rawId) }
            if let c = current, c["encrypted"].truthy {
                try ownerCheck(c, rawId, "making it non-private")
                if !hasData {
                    if c["encrypted"]?["status"] == .string("failed") {
                        throw Enc.err("Cannot make record \"\(rawId)\" non-private: its current contents could not be decrypted " +
                                      "(\(c["encrypted"]?["reason"]?.pyString ?? "")), so they cannot be written back in the clear. " +
                                      "Unlock encryption, or supply the record's data with the access group change.", "ENCRYPTION_LOCKED")
                    }
                    value = c["data"] ?? .null
                    hasData = true
                }
            }
            if let c = current, Skapi.hasBin(c, encrypted: true) {
                files = "decrypt"
            } else if let c = current, let r = c["record_id"]?.string {
                s.deks[r] = nil
            }
            return EncResult(send: value, omit: !hasData, files: files)
        }
        if tableName == s.cfg.table { return EncResult(send: value, omit: !hasData) }  // the keyring itself is never sealed
        if !hasData { return EncResult(omit: true) }
        if value[Enc.withheld] == .bool(true) {
            throw Enc.err("This record's data could not be decrypted by this session, so it cannot be written back. " +
                          "Writing it would replace the record with the placeholder.", "ENCRYPTION_CANNOT_REWRITE_WITHHELD")
        }
        await awaitEncReady()
        guard s.status == "unlocked", let mk = s.mk else {
            throw Enc.err("Encryption is enabled but locked, so this private record cannot be written. " +
                          "Call unlockEncryption(password:) first, or the user must log in with their password.", "ENCRYPTION_LOCKED")
        }
        if value.object?.contains(Enc.envMarker) == true { throw Enc.err("\"__skapi_enc__\" is a reserved key in record data.", "INVALID_PARAMETER") }
        if (view["service"].truthy && view["service"]?.string != service) || (view["owner"].truthy && view["owner"]?.string != owner) {
            throw Enc.err("Encrypted records cannot be written to another project. The encryption key is derived per project, " +
                          "so a record written under one service and read under another could never be decrypted. " +
                          "Construct a separate Skapi instance for that project.", "INVALID_REQUEST")
        }
        let myId = me
        if myId.isEmpty { throw Enc.err("User login is required to write an encrypted record.", "INVALID_REQUEST") }
        var rolling = false
        var rollKey: Data?
        var priorCt: [String] = []
        if !rawId.isEmpty && s.roll.contains(rawId) {
            s.roll.remove(rawId)
            rollKey = s.rollKey.removeValue(forKey: rawId)
            let stale = s.deks.removeValue(forKey: rawId)
            priorCt = ([stale?.ctURL ?? ""] + (stale?.ctStale ?? [])).filter { !$0.isEmpty }
            rolling = true
        }
        var files: String?
        var entry = rawId.isEmpty ? nil : try await dekIfCurrent(rawId)
        var resolvedId = ""
        var uid = view["unique_id"]?.string ?? ""
        var current: JSONObject?
        if !rawId.isEmpty && entry == nil {
            current = try? await readOwnRecord(rawId)
            try ownerCheck(current, rawId, "updating it")
        }
        if let c = current {
            if !c["encrypted"].truthy && Skapi.hasBin(c, encrypted: false) { files = "encrypt" }
            resolvedId = c["record_id"]?.string ?? ""
            if uid.isEmpty { uid = c["unique_id"]?.string ?? "" }
            if c["encrypted"]?["status"] == .string("failed") {
                throw Enc.err("Cannot update encrypted record \"\(rawId)\": its current contents could not be decrypted (\(c["encrypted"]?["reason"]?.pyString ?? "")), " +
                              "so its existing key wraps cannot be preserved. Updating anyway would revoke everyone it is shared with.", "ENCRYPTION_LOCKED")
            }
            if !rolling { entry = s.deks[resolvedId] }
        }
        if let e = entry {
            if !e.rid.isEmpty { resolvedId = e.rid }
            if e.anch == "uid" { uid = e.uid.isEmpty ? uid : e.uid }
            if e.own != myId {
                throw Enc.err("Record \"\(rawId)\" belongs to another user (\(e.own)). Encryption only operates on records you own.", "ENCRYPTION_NOT_RECORD_OWNER")
            }
        } else if !rawId.isEmpty && resolvedId.isEmpty && !rolling {
            resolvedId = rawId
        }
        let dek = entry?.bytes ?? rollKey ?? Prim.randomBytes(32)
        var recipients = entry?.recipients ?? JSONObject()
        let anch = !uid.isEmpty ? "uid" : (!resolvedId.isEmpty ? "rid" : "new")
        let anchor = anch == "uid" ? uid : anch == "rid" ? resolvedId : ""
        let aad = payloadAAD(myId, anch, anchor)
        var mine: JSONObject = ["t": "mk"]
        for (k, v) in try Enc.seal(mk, dek, recipientAAD(aad, myId, "mk")) { mine[k] = v }
        recipients[myId] = .object(mine)
        if let e = entry, e.anch != anch || Skapi.anchorOf(e.anch, uid: e.uid, rid: e.rid) != anchor {
            recipients = try await rewrapAll(dek, recipients, myId, anch, anchor, aad)
        }
        let (iv, ct) = try Enc.sealRaw(dek, utf8(value.jsonString), aad)
        var env: JSONObject = [Enc.envMarker: 1, "enc": "A256GCM", "kw": "ECDH-ES+A256GCM", "anch": .string(anch), "uid": .string(uid),
                               "rid": .string(resolvedId), "own": .string(myId), "iv": .string(B64.url(iv)), "ct": .string(B64.url(ct)),
                               "k": .object(recipients)]
        var spill: Data?
        var retire: [String]?
        if !resolvedId.isEmpty && (env["ct"]?.string?.count ?? 0) > Enc.spillLimit {
            spill = ct
            env["ct"] = ""
            env["ct_ref"] = .string(Enc.ctFileSuffix)
        }
        if !resolvedId.isEmpty {
            // the stored payload files' real urls, retired whether the new data spills again or now fits inline
            var seen = Set<String>()
            let old = ([entry?.ctURL ?? ""] + (entry?.ctStale ?? []) + priorCt).filter { !$0.isEmpty && seen.insert($0).inserted }
            retire = old.isEmpty ? nil : old
        }
        let envSize = JSON.object(env).asciiJSONString.utf8.count
        if envSize > Enc.envelopeCap {
            throw Enc.err("Encrypted record data is too large: once encrypted and base64 encoded it becomes \(envSize) bytes, " +
                          "over the \(Enc.envelopeCap) byte limit. Encryption costs about 33% plus roughly 230 bytes per additional recipient.",
                          "ENCRYPTED_DATA_TOO_LARGE")
        }
        if !resolvedId.isEmpty { cacheDek(resolvedId, dek, recipients, anch, uid, myId) }
        let dekEntry = DekEntry(bytes: dek, recipients: recipients, anch: anch, uid: uid, own: myId)
        return EncResult(send: .object(env), encrypted: true, plain: value, dek: dekEntry, spill: spill, retire: retire, files: files,
                         recipients: recipients.keys)
    }

    /// A record's cached data key, only while the stored envelope still carries the key wraps it was
    /// cached with (another session of the owner may have rolled it).
    func dekIfCurrent(_ key: String) async throws -> DekEntry? {
        guard let s = enc, let entry = s.deks[key] else { return nil }
        let rid = entry.rid.isEmpty ? key : entry.rid
        let stored = try await readStoredEnvelope(rid)
        if let st = stored, st["k"]?.object == entry.recipients { return entry }
        s.deks[key] = nil
        s.deks[rid] = nil
        return nil
    }

    /// A just-created record's key, under the record_id the server minted.
    func bindRecordDek(_ recordId: String, _ dekEntry: DekEntry?) {
        guard let s = enc, var e = dekEntry, !recordId.isEmpty, s.deks[recordId] == nil else { return }
        e.rid = recordId
        s.deks[recordId] = e
    }

    /// Re-uploads a record's attachments sealed ("encrypt") or in the clear ("decrypt"); returns the urls to retire.
    func convertRecordFiles(_ recordId: String, direction: String) async throws -> [String] {
        guard let s = enc, let rec = try await readOwnRecord(recordId) else { return [] }
        let wantSealed = direction == "decrypt"
        var targets: [(String, JSONObject)] = []
        for (formKey, entries) in rec["bin"]?.object ?? JSONObject() {
            for f in entries.array ?? [] {
                if let fo = f.object, (fo["encrypted"]?.truthy ?? false) == wantSealed { targets.append((formKey, fo)) }
            }
        }
        if targets.isEmpty { return [] }
        var uploads: [PreparedFile] = []
        var retire: [String] = []
        for (formKey, f) in targets {
            let url = f["url"]?.string ?? ""
            guard case .bytes(var content) = try await getFileInternal(url, dataType: .bytes, expires: nil, raw: true) else { continue }
            var contentType: String?
            if wantSealed {
                let (plain, meta) = try decryptFileFor(url, content)
                content = plain
                contentType = meta["t"].truthy ? meta["t"]?.string : "application/octet-stream"
            }
            let filename = f["filename"]?.string ?? ""
            uploads.append(PreparedFile(name: formKey, filename: filename, content: content,
                                        contentType: contentType ?? Mime.guess(filename) ?? "application/octet-stream"))
            if let parts = Check.splitURL(url) { retire.append("\(parts.scheme)://\(parts.netloc)/\(f["path"]?.pyString ?? "")") }
        }
        // the key leaves the cache for the upload (or the upload would seal the files again), and comes
        // back if anything fails: all or nothing, as in skapi-js
        let held = wantSealed ? s.deks.removeValue(forKey: recordId) : nil
        let result: UploadResult
        do {
            result = try await uploadPrepared(uploads, recordId: recordId)
        } catch {
            if let h = held { s.deks[recordId] = h }
            throw error
        }
        if let first = result.errors.first {
            if let h = held { s.deks[recordId] = h }
            let landed = result.landed.filter { !$0.isEmpty }
            if !landed.isEmpty {
                do { try await removeLandedCopies(recordId, landed) }
                catch { warn("could not remove the partly converted copies: \(error)") }
            }
            throw Enc.err("The record's attached files could not all be converted, so the record was not changed: \(first.error)", first.error.code)
        }
        return retire
    }

    /// A record file joins the record's file list a moment after its upload: wait for them to appear,
    /// then remove them in one write.
    func removeLandedCopies(_ recordId: String, _ urls: [String]) async throws {
        func bare(_ u: String) -> String { (u.components(separatedBy: "?")[0]).removingPercentEncoding ?? u }
        let want = Set(urls.map(bare))
        for attempt in 0..<8 {
            let rec = try await readOwnRecord(recordId) ?? JSONObject()
            var have = Set<String>()
            for (_, entries) in rec["bin"]?.object ?? JSONObject() {
                for f in entries.array ?? [] { have.insert(bare(f["url"]?.string ?? "")) }
            }
            if want.isSubset(of: have) { break }
            try? await Task.sleep(nanoseconds: UInt64(0.5 * Double(attempt + 1) * 1_000_000_000))
        }
        try await postRecord(config: ["record_id": .string(recordId), "remove_bin": .array(urls.map { .string($0) })])
    }

    func rewrapAll(_ dek: Data, _ recipients: JSONObject, _ myId: String, _ anch: String, _ anchor: String, _ aad: Data) async throws -> JSONObject {
        var out: JSONObject = [myId: recipients[myId]!]
        let others = recipients.keys.filter { $0 != myId }
        let keys = others.isEmpty ? [:] : try await peerKeys(others)
        for u in others {
            guard let k = keys[u] else { continue }  // as in skapi-js: a grantee whose key cannot be found is dropped
            var w: JSONObject = ["t": "ecdh"]
            for (kk, v) in try Enc.ecdhWrap(dek, peerPub: k.0, info: wrapInfo(anchor, myId, u, k.1), aad: recipientAAD(aad, u, k.1)) { w[kk] = v }
            w["fpr"] = .string(k.1)
            out[u] = .object(w)
        }
        return out
    }

    func cacheDek(_ rid: String, _ dek: Data, _ recipients: JSONObject, _ anch: String, _ uid: String, _ own: String,
                  ctURL: String = "", ctStale: [String]? = nil) {
        guard let s = enc else { return }
        var e = s.deks[rid] ?? DekEntry(bytes: dek, recipients: recipients, anch: anch, uid: uid, own: own)
        e.bytes = dek
        e.recipients = recipients
        e.anch = anch
        e.uid = uid
        e.rid = rid
        e.own = own
        e.accessGroup = "private"
        if !ctURL.isEmpty {
            e.ctURL = ctURL
            e.ctStale = ctStale ?? []
        }
        s.deks[rid] = e
    }

    // ---- read ----------------------------------------------------------------------------------------

    /// (value, flag). Never throws.
    func maybeDecrypt(_ raw: JSON, _ ctx: DecryptContext) async -> (JSON, JSON?) {
        guard Enc.isEnvelope(raw), ctx.accessGroup == .string("private"), let o = raw.object else { return (raw, nil) }
        guard let s = enc else { return (.null, ["status": "failed", "reason": "ENCRYPTION_DISABLED"]) }
        if ctx.tableName == s.cfg.table { return (raw, nil) }
        await awaitEncReady()

        func fail(_ reason: String, _ recipients: [String]? = nil) -> (JSON, JSON?) {
            var flag: JSONObject = ["status": "failed", "reason": .string(reason)]
            if let r = recipients { flag["recipients"] = .array(r.map { .string($0) }) }
            if s.cfg.withheld == .sentinel {
                var v: JSONObject = [Enc.withheld: true, "reason": .string(reason)]
                if reason == "NOT_A_RECIPIENT" { v["recipients"] = .array((recipients ?? []).map { .string($0) }) }
                return (.object(v), .object(flag))
            }
            return (.null, .object(flag))
        }

        if o[Enc.envMarker] != .number(1) { return fail("UNSUPPORTED_VERSION") }
        let own = o["own"]?.string ?? ""
        let envUid = o["uid"]?.string ?? "", envRid = o["rid"]?.string ?? ""
        if own != ctx.userId || (!envUid.isEmpty && !(ctx.uniqueId ?? "").isEmpty && envUid != ctx.uniqueId)
            || (!envRid.isEmpty && !ctx.recordId.isEmpty && envRid != ctx.recordId) {
            return fail("BINDING_MISMATCH")
        }
        let k = o["k"]?.object ?? JSONObject()
        let myId = me
        guard let wrap = k[myId]?.object else { return fail("NOT_A_RECIPIENT", k.keys) }
        if s.status != "unlocked" { return fail("NO_SESSION_KEY") }
        let anch = o["anch"]?.string ?? ""
        let anchor = Skapi.anchorOf(anch, uid: envUid, rid: envRid)
        let aad = payloadAAD(own, anch, anchor)
        let dek: Data
        do {
            if wrap["t"] == .string("mk") {
                guard let mk = s.mk else { return fail("NO_SESSION_KEY") }
                dek = try Enc.open(mk, B64.urlDecode(wrap["iv"]?.string), B64.urlDecode(wrap["ct"]?.string), recipientAAD(aad, myId, "mk"))
            } else if wrap["t"] == .string("ecdh") {
                guard let priv = s.ikPriv else { return fail("NO_SESSION_KEY") }
                let fpr = wrap["fpr"]?.string ?? ""
                dek = try Enc.ecdhUnwrap(priv, wrap, info: wrapInfo(anchor, own, myId, fpr), aad: recipientAAD(aad, myId, fpr))
            } else {
                return fail("UNSUPPORTED_VERSION")
            }
        } catch {
            return fail("BAD_KEY")
        }
        var ctUsed = "", ctStale: [String] = []
        var value: JSON = .null
        if o["ct_ref"].truthy {
            // newest payload file first; the first one that passes the GCM tag check is the current one
            let candidates = ctx.ctURLs.isEmpty ? (ctx.ctURL.map { [$0] } ?? []) : ctx.ctURLs
            var fetched = false
            for url in candidates {
                guard case .bytes(let ct)? = try? await getFileInternal(url, dataType: .bytes, expires: nil) else { continue }
                fetched = true
                if let iv = try? B64.urlDecode(o["iv"]?.string), let plain = try? Enc.open(dek, iv, ct, aad), let v = try? JSON.parse(utf8Decode(plain)) {
                    value = v
                    ctUsed = url
                    break
                }
            }
            if ctUsed.isEmpty { return fail(fetched ? "CORRUPT" : "DATA_UNAVAILABLE") }
            ctStale = candidates.filter { $0 != ctUsed }
        } else {
            guard let ct = try? B64.urlDecode(o["ct"]?.string) else { return fail("DATA_UNAVAILABLE") }
            guard let iv = try? B64.urlDecode(o["iv"]?.string), let plain = try? Enc.open(dek, iv, ct, aad),
                  let v = try? JSON.parse(utf8Decode(plain)) else { return fail("CORRUPT") }
            value = v
        }
        if !ctx.recordId.isEmpty { cacheDek(ctx.recordId, dek, k, anch, envUid, own, ctURL: ctUsed, ctStale: ctStale) }
        return (value, ["status": "encrypted", "recipients": .array(k.keys.map { .string($0) })])
    }

    // ---- files ---------------------------------------------------------------------------------------

    func maybeEncryptFile(_ recordId: String, _ entry: PreparedFile) throws -> PreparedFile {
        guard let s = enc, entry.name != Enc.ctKey else { var e = entry; e.presealed = false; return e }
        if entry.presealed { var e = entry; e.presealed = false; return e }  // already sealed by a revoke, under the key its roll installs
        if entry.name.contains(Enc.fileMarker) { throw Enc.err("\"__skenc__\" is reserved in an upload form key.", "INVALID_PARAMETER") }
        guard let d = s.deks[recordId] else { return entry }  // as in skapi-js: without the record's key cached, the file goes up as is
        let container = try Enc.encryptFile(dek: d.bytes, ctx: .init(service: service, owner: owner, recordOwner: d.own, recordId: recordId),
                                            content: entry.content, name: entry.filename, contentType: entry.contentType, lastModified: 0)
        return PreparedFile(name: "\(entry.name)\(Enc.fileMarker)\(Enc.base62(entry.content.count))", filename: entry.filename, content: container,
                            contentType: "application/octet-stream")
    }

    /// Before files are sealed with a record's cached data key: the key must still be the record's.
    func confirmFileDek(_ recordId: String?) async throws {
        guard let s = enc, let rid = recordId, !rid.isEmpty, s.deks[rid] != nil else { return }
        if try await dekIfCurrent(rid) != nil { return }
        guard let rec = try await readOwnRecord(rid), rec["encrypted"].truthy else { return }
        if let r = rec["record_id"]?.string, r != rid, let e = s.deks[r] { s.deks[rid] = e }
        if s.deks[rid] == nil {
            throw Enc.err("Cannot attach files to encrypted record \"\(rid)\": its data key changed on another device and could not " +
                          "be read here (\(rec["encrypted"]?["reason"]?.pyString ?? "")).", "ENCRYPTION_LOCKED")
        }
    }

    static func sealedFileSegments(_ url: String) -> [String]? {
        let segs = Array(url.components(separatedBy: "?")[0].components(separatedBy: "/").dropFirst(3))
        if segs.count < 12 || segs[4] != "records" || segs[7] != "bin" || Enc.parseFileMarker(segs[10]) == nil { return nil }
        return segs
    }

    func maybeDecryptFile(_ requestedURL: String, _ blob: Data) async throws -> Data {
        guard enc != nil, Skapi.sealedFileSegments(requestedURL) != nil else { return blob }
        await awaitEncReady()
        return try decryptFileFor(requestedURL, blob).0
    }

    func decryptFileFor(_ requestedURL: String, _ blob: Data) throws -> (Data, JSONObject) {
        guard let segs = Skapi.sealedFileSegments(requestedURL), let s = enc else { return (blob, JSONObject()) }
        guard let d = s.deks[segs[5]] else {
            throw Enc.err("Cannot open this file: the data key for record \"\(segs[5])\" is not available. Read the record first, and make sure encryption is unlocked.",
                          "ENCRYPTION_LOCKED")
        }
        if !Enc.isEncryptedFile(blob) {
            throw Enc.err("This file is marked as encrypted but its contents are not an encrypted container.", "ENCRYPTION_FILE_CORRUPT")
        }
        return try Enc.decryptFile(dek: d.bytes, ctx: .init(service: service, owner: owner, recordOwner: segs[3], recordId: segs[5]), blob: blob)
    }

    // ---- sharing ---------------------------------------------------------------------------------------

    func loadForRewrap(_ recordId: String) async throws -> DekEntry? {
        if let e = try await dekIfCurrent(recordId) { return e }
        guard let rec = try await readOwnRecord(recordId) else { throw Enc.err("Record \"\(recordId)\" not found.", "NOT_EXISTS") }
        let e = rec["encrypted"]
        if e?["status"] == .string("failed") && e?["reason"] == .string("DATA_UNAVAILABLE") {
            throw Enc.err("Cannot change sharing on record \"\(recordId)\": its data could not be read, " +
                          "so whether it is encrypted is unknown. Retry once the record reads normally.", "ENCRYPTION_DATA_UNAVAILABLE")
        }
        if !(e?.truthy ?? false) { return nil }
        if rec["user_id"]?.string != me {
            throw Enc.err("Only the record owner can share an encrypted record, because adding a key wrap means writing the record.", "ENCRYPTION_GRANT_REQUIRES_OWNER")
        }
        guard let entry = enc?.deks[rec["record_id"]?.string ?? ""] else {
            throw Enc.err("Cannot change sharing on record \"\(recordId)\": its data could not be decrypted (\(e?["reason"]?.pyString ?? "")).", "ENCRYPTION_LOCKED")
        }
        return entry
    }

    /// The record's stored envelope, as the server holds it (nil when it is not one), never decrypted.
    func readStoredEnvelope(_ recordId: String) async throws -> JSONObject? {
        let q: JSON = Rx.match("^[a-zA-Z0-9]+$", recordId) ? ["record_id": .string(recordId)] : ["unique_id": .string(recordId)]
        let (built, _) = try await buildQuery(q, isDelete: false)
        let signedIn = await self.signedIn()
        let res = try await call("get-records", .object(built), auth: signedIn, method: signedIn ? "POST" : "GET", fetchOptions: ["limit": 1])
        guard let raw = res["list"]?[0], raw.isObject else { return nil }
        let rec = try await normalizeRecord(raw, skipBinResolve: true, skipDecrypt: true)
        return Enc.isEnvelope(rec["data"]) ? rec["data"]?.object : nil
    }

    func writeRecipients(_ recordId: String, _ recipients: JSONObject) async throws {
        guard var stored = try await readStoredEnvelope(recordId) else {
            throw Enc.err("Cannot change sharing on record \"\(recordId)\": its stored envelope could not be read.", "ENCRYPTION_DATA_UNAVAILABLE")
        }
        enc?.deks[recordId]?.recipients = recipients
        stored["k"] = .object(recipients)
        enc?.passthrough[recordId] = .object(stored)
        try await postRecord(config: ["record_id": .string(recordId)])
    }

    func encAddRecipients(_ recordId: String, _ ids: [String]) async throws {
        guard enc != nil, !ids.isEmpty else { return }
        guard let entry = try await loadForRewrap(recordId) else { return }
        let myId = me
        if entry.own != myId {
            throw Enc.err("Only the record owner can share an encrypted record, because adding a key wrap means writing the record.", "ENCRYPTION_GRANT_REQUIRES_OWNER")
        }
        let targets = ids.filter { $0 != myId }
        let keys = try await peerKeys(targets)
        let missing = targets.filter { keys[$0] == nil }
        if !missing.isEmpty {
            throw Enc.err("These users have no encryption key yet, so they cannot be given access: \(missing.joined(separator: ", ")). " +
                          "A user's key is created the first time they log in with encryption enabled.", "ENCRYPTION_RECIPIENT_HAS_NO_KEY")
        }
        var recipients = entry.recipients
        let anchor = Skapi.anchorOf(entry.anch, uid: entry.uid, rid: entry.rid)
        let aad = payloadAAD(entry.own, entry.anch, anchor)
        for u in targets {
            let (pub, fpr) = keys[u]!
            var w: JSONObject = ["t": "ecdh"]
            for (k, v) in try Enc.ecdhWrap(entry.bytes, peerPub: pub, info: wrapInfo(anchor, entry.own, u, fpr), aad: recipientAAD(aad, u, fpr)) { w[k] = v }
            w["fpr"] = .string(fpr)
            recipients[u] = .object(w)
        }
        try await writeRecipients(recordId, recipients)
    }

    func encDropAndRoll(_ recordId: String, _ ids: [String]?) async throws {
        guard let s = enc else { return }
        guard let entry = try await loadForRewrap(recordId) else { return }
        let myId = me
        if entry.own != myId { throw Enc.err("Only the record owner can revoke access to an encrypted record.", "ENCRYPTION_GRANT_REQUIRES_OWNER") }
        // the plaintext FIRST, while the current key is still usable
        let rec = try await readOwnRecord(recordId)
        guard let r = rec, r["encrypted"]?["status"] != .string("failed") else {
            throw Enc.err("Cannot change sharing on record \"\(recordId)\": its current data could not be read " +
                          "(\(rec?["encrypted"]?["reason"]?.pyString ?? "None")), so re-writing the record would destroy it.", "ENCRYPTION_DATA_UNAVAILABLE")
        }
        let rid = r["record_id"]?.string.flatMap { $0.isEmpty ? nil : $0 } ?? recordId
        // who keeps access, from the record just read rather than an older cached map
        let current = s.deks[rid] ?? entry
        let keep = ids == nil ? [] : current.recipients.keys.filter { $0 != myId && !ids!.contains($0) }
        let keys = keep.isEmpty ? [:] : try await peerKeys(keep)
        let missing = keep.filter { keys[$0] == nil }
        if !missing.isEmpty {
            throw Enc.err("Cannot revoke on record \"\(recordId)\": these users keep access but their encryption keys could not be read, " +
                          "so re-sharing after the key roll would fail and lock them out: \(missing.joined(separator: ", ")).", "ENCRYPTION_RECIPIENT_HAS_NO_KEY")
        }
        // the new data key, minted now so the sealed attachments are sealed again under it BEFORE the roll
        let nextKey = Prim.randomBytes(32)
        let ctx = Enc.FileContext(service: service, owner: owner, recordOwner: myId, recordId: rid)
        var reseal: [PreparedFile] = []
        var retire: [String] = []
        for (formKey, entries) in r["bin"]?.object ?? JSONObject() {
            for f in entries.array ?? [] where f["encrypted"].truthy {
                let url = f["url"]?.string ?? ""
                let filename = f["filename"]?.string ?? ""
                let content: Data, meta: JSONObject
                do {
                    guard case .bytes(let blob) = try await getFileInternal(url, dataType: .bytes, expires: nil, raw: true) else { continue }
                    (content, meta) = try decryptFileFor(url, blob)
                } catch let e as SkapiError where e.code == "ENCRYPTION_FILE_STALE_KEY" {
                    continue  // sealed under a key an earlier roll retired: nobody can open it, and it must not block this revoke
                } catch {
                    throw Enc.err("Cannot revoke on record \"\(recordId)\": its encrypted file \"\(filename)\" could not be read, " +
                                  "so rolling the key would lock it: \(error)", "ENCRYPTION_DATA_UNAVAILABLE")
                }
                let ct = (meta["t"].truthy ? meta["t"]?.string : nil) ?? Mime.guess(filename) ?? "application/octet-stream"
                reseal.append(PreparedFile(name: "\(formKey)\(Enc.fileMarker)\(Enc.base62(content.count))", filename: filename,
                                           content: try Enc.encryptFile(dek: nextKey, ctx: ctx, content: content, name: filename, contentType: ct,
                                                                        lastModified: meta["lm"]?.int ?? 0),
                                           contentType: "application/octet-stream", presealed: true))
                if let parts = Check.splitURL(url) { retire.append("\(parts.scheme)://\(parts.netloc)/\(f["path"]?.pyString ?? "")") }
            }
        }
        var copies: [String] = []
        if !reseal.isEmpty {
            let result = try await uploadPrepared(reseal, recordId: rid)
            copies = result.landed.filter { !$0.isEmpty }
            if let first = result.errors.first {
                if !copies.isEmpty {
                    do { try await removeLandedCopies(rid, copies) }
                    catch { warn("encryption: the re-sealed copies could not be removed: \(error)") }
                }
                throw first.error
            }
        }
        s.roll.insert(rid)
        s.rollKey[rid] = nextKey
        var config: JSONObject = ["record_id": .string(rid), "table": ["name": r["table"]?["name"] ?? "", "access_group": "private"]]
        if !retire.isEmpty { config["remove_bin"] = .array(retire.map { .string($0) }) }
        do {
            try await postRecord(r["data"] ?? .null, config: .object(config))
            s.roll.remove(rid)
            s.rollKey[rid] = nil
        } catch {
            // never left for a later write: a pending roll writes a key wrapped for the owner only
            s.roll.remove(rid)
            s.rollKey[rid] = nil
            if !copies.isEmpty {
                do { try await dropUnrolledCopies(rid, nextKey, copies) }
                catch { warn("encryption: the re-sealed copies could not be removed: \(error)") }
            }
            throw error
        }
        if !keep.isEmpty { try await encAddRecipients(rid, keep) }
    }

    /// After a failed roll write: removes the re-sealed copies, unless the write landed after all.
    func dropUnrolledCopies(_ recordId: String, _ nextKey: Data, _ copies: [String]) async throws {
        guard let s = enc, let mk = s.mk else { return }
        let myId = me
        guard let raw = try await readStoredEnvelope(recordId), !myId.isEmpty, let w = raw["k"]?[myId]?.object, w["t"] == .string("mk"),
              raw["own"]?.string == myId else { return }
        let anch = raw["anch"]?.string ?? ""
        let aad = recipientAAD(payloadAAD(myId, anch, Skapi.anchorOf(anch, uid: raw["uid"]?.string, rid: raw["rid"]?.string)), myId, "mk")
        guard let iv = try? B64.urlDecode(w["iv"]?.string), let ct = try? B64.urlDecode(w["ct"]?.string),
              let stored = try? Enc.open(mk, iv, ct, aad) else { return }
        if stored != nextKey { try await removeLandedCopies(recordId, copies) }
    }

    // ---- public methods ------------------------------------------------------------------------------

    /// ["status": "disabled" | "locked" | "unlocked", "reason"?, "user_id"?, "fingerprint"?].
    public func getEncryptionStatus() async -> JSON {
        guard let s = enc else { return ["status": "disabled"] }
        await restore()
        await awaitEncReady()
        var out: JSONObject = ["status": .string(s.status)]
        if s.status != "unlocked" { out["reason"] = .string(s.reason) }
        if !s.userId.isEmpty { out["user_id"] = .string(s.userId) }
        if !s.fpr.isEmpty { out["fingerprint"] = .string(s.fpr) }
        return .object(out)
    }

    /// true for the placeholder a record reads as when this session cannot decrypt it (withheld: .sentinel).
    public nonisolated func isWithheld(_ value: JSON?) -> Bool { value?[Enc.withheld] == .bool(true) }

    /// Opens encryption with the password, for a session restored from storage without a remembered device key.
    @discardableResult
    public func unlockEncryption(password: String) async throws -> JSON {
        guard let s = enc else { throw Enc.err("Encryption is not enabled for this instance.", "INVALID_REQUEST") }
        if !(await signedIn()) { throw Enc.err("User login is required.", "INVALID_REQUEST") }
        if password.isEmpty { throw Enc.err("\"password\" is required.", "INVALID_PARAMETER") }
        await awaitEncReady()
        try await ensureKeyring(password, create: false)  // opens an existing keyring only
        if s.status != "unlocked" { throw Enc.err("Encryption could not be unlocked: \(s.reason)", "ENCRYPTION_LOCKED") }
        return ["status": "unlocked"]
    }

    /// Drops every key from memory. forgetDevice: true also removes the key this device remembers.
    @discardableResult
    public func lockEncryption(forgetDevice: Bool = false) async -> JSON {
        guard let s = enc else { return ["status": "disabled"] }
        if forgetDevice { deleteDevice() }
        // keeps an encryption recovery code the app has not collected yet: it can never be shown again
        s.clear(keepRecovery: true)
        return ["status": "locked"]
    }

    func encryptionRecoveryInfo() async -> JSON? {
        guard let s = enc, await signedIn() else { return nil }
        if s.cfg.recovery != .code {
            return ["code": nil, "message": "Encryption recovery codes are turned off (\"encryption.recovery\" is \"none\")."]
        }
        if let code = s.pendingRecoveryCode, !code.isEmpty, s.pendingRecoveryUser == me {
            s.pendingRecoveryCode = nil
            s.pendingRecoveryUser = ""
            return ["code": .string(code), "message": .string("This is your encryption recovery code. Save it now: it is shown only this once. " +
                    "If you forget your password, it is the only way to read your encrypted private data again.")]
        }
        if s.status != "unlocked" {
            return ["code": nil, "message": .string("Encryption is locked. Unlock it with unlockEncryption() or unlockEncryptionWithRecoveryCode(), " +
                    "then call regenerateEncryptionRecoveryCode() to get a new encryption recovery code.")]
        }
        return ["code": nil, "message": .string("Your encryption recovery code was shown once and cannot be shown again. " +
                "Call regenerateEncryptionRecoveryCode() to get a new one.")]
    }

    /// Opens encryption with the encryption recovery code (after a forgotten password was reset and
    /// the user signed in again). password: the new password, to wrap the keyring under it again.
    /// Returns ["status", "repaired", "encryptionRecoveryCode"] with a new code.
    @discardableResult
    public func unlockEncryptionWithRecoveryCode(_ code: String, password: String? = nil) async throws -> JSON {
        guard let s = enc else { throw Enc.err("Encryption is not enabled for this instance.", "INVALID_REQUEST") }
        if !(await signedIn()) {
            throw Enc.err("User login is required. Reset the password and log in first, then use the encryption recovery code.", "INVALID_REQUEST")
        }
        if code.isEmpty { throw Enc.err("\"code\" is required.", "INVALID_PARAMETER") }
        let uid = me
        guard let keyring = try await findKeyring(uid) else {
            throw Enc.err("This account has no encryption keyring, so there is nothing to recover.", "NOT_EXISTS")
        }
        let raw = try Enc.decodeRecoveryCode(code)
        var data = keyring["data"]?.object ?? JSONObject()
        var mk: Data?
        let recoveryWraps = (data["wraps"]?.array ?? []).filter { $0["p"] == .string("recovery") }
            .sorted { ($0["created"]?.number ?? 0) > ($1["created"]?.number ?? 0) }
        for w in recoveryWraps {
            guard let sv = w["kdf"]?["s"]?.string, let salt = try? B64.urlDecode(sv), let iv = try? B64.urlDecode(w["iv"]?.string),
                  let ct = try? B64.urlDecode(w["ct"]?.string) else { continue }
            let rk = Enc.hkdf(raw, salt: salt, info: eS("recovery", uid))
            if let m = try? Enc.open(rk, iv, ct, utf8("\(eS("rk", uid))|HKDF-SHA256|\(sv)")) { mk = m; break }
        }
        guard let masterKey = mk else {
            throw Enc.err("That encryption recovery code did not open the keyring. Check it against the copy you saved when encryption was set up.",
                          "ENCRYPTION_BAD_RECOVERY_CODE")
        }
        try await adoptKeyring(keyring, masterKey, uid)
        var wraps = data["wraps"]?.array ?? []
        var repaired = false
        var newCode: String?
        if let p = password, !p.isEmpty {
            wraps = wraps.filter { $0["p"] != .string("password") } + [try passwordWrap(masterKey, p, uid)]
            repaired = true
        }
        if s.cfg.recovery == .code {
            let (w, c) = try recoveryWrap(masterKey, uid)
            wraps = wraps.filter { $0["p"] != .string("recovery") } + [w]
            newCode = c
        }
        data["wraps"] = .array(wraps)
        data["updated"] = .number(nowMs())
        try await postRecord(.object(data), config: ["record_id": keyring["record_id"] ?? .null])
        if s.cfg.persistDevice { saveDevice() }
        return ["status": "unlocked", "repaired": .bool(repaired), "encryptionRecoveryCode": newCode.map { .string($0) } ?? .null]
    }

    /// Retires the current encryption recovery code and issues a new one: ["encryptionRecoveryCode": code].
    @discardableResult
    public func regenerateEncryptionRecoveryCode() async throws -> JSON {
        guard let s = enc else { throw Enc.err("Encryption is not enabled for this instance.", "INVALID_REQUEST") }
        guard s.status == "unlocked", let currentMk = s.mk else {
            throw Enc.err("Encryption must be unlocked to issue an encryption recovery code. Only someone who can already decrypt can create one.", "ENCRYPTION_LOCKED")
        }
        if s.cfg.recovery == .none {
            throw Enc.err("Encryption recovery codes are turned off for this instance (\"encryption.recovery\" is \"none\").", "INVALID_REQUEST")
        }
        let res = try await getRecords(["record_id": .string(s.keyringRecordId)], fetchOptions: ["limit": 1])
        guard var data = res["list"]?[0]?["data"]?.object else {
            throw Enc.err("The encryption keyring could not be read.", "ENCRYPTION_KEYRING_CORRUPT")
        }
        guard let selfWrap = data["self"]?.object, selfWrap["ct"].truthy else {
            throw Enc.err("This keyring predates encryption recovery code rotation and cannot issue a new code. " +
                          "Use unlockEncryptionWithRecoveryCode() with the existing code, which issues a replacement.", "ENCRYPTION_KEYRING_CORRUPT")
        }
        let mk = try Enc.open(currentMk, B64.urlDecode(selfWrap["iv"]?.string), B64.urlDecode(selfWrap["ct"]?.string), utf8(eS("self", s.userId)))
        let (w, code) = try recoveryWrap(mk, s.userId)
        data["wraps"] = .array((data["wraps"]?.array ?? []).filter { $0["p"] != .string("recovery") } + [w])
        data["updated"] = .number(nowMs())
        try await postRecord(.object(data), config: ["record_id": .string(s.keyringRecordId)])
        return ["encryptionRecoveryCode": .string(code)]
    }

    /// Trusts a peer's key fingerprint (checked out of band), replacing an earlier pin.
    public func pinPeerKey(userId: String, fingerprint: String) async throws {
        guard let s = enc, s.status == "unlocked" else { throw Enc.err("Encryption is locked.", "ENCRYPTION_LOCKED") }
        s.pins[userId] = fingerprint
        s.peerPub[userId] = nil
        try await persistPins()
    }
}

func nowMs() -> Double { (Date().timeIntervalSince1970 * 1000).rounded(.down) }
