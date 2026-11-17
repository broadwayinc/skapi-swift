import Foundation

/// Options for client-side record encryption.
///
/// Only `record.data` of PRIVATE records is sealed, with a per-record key. That key is wrapped for
/// the owner under a master key only the user's password (or encryption recovery code) opens, and
/// for each user the record is shared with through ECDH P-256. Compatible byte for byte with
/// skapi-js and skapi-py: a record sealed by any of them opens in the others.
public struct EncryptionOptions: Sendable {
    public enum TrustPolicy: String, Sendable { case tofu, strict }
    public enum Withheld: String, Sendable { case null, sentinel }
    public enum Recovery: String, Sendable { case code, none }

    /// PBKDF2 iterations for the password wrap (at least 100000).
    public var iterations: Int
    /// tofu: a peer's first seen key is pinned on first use. strict: peers must be pinned with `pinPeerKey` first.
    public var trustPolicy: TrustPolicy
    /// What a record this session cannot decrypt reads as: null, or a `["__skapi_no_access__": true, ...]` sentinel.
    public var withheld: Withheld
    /// code: an encryption recovery code is created when encryption is first set up. none: no code.
    public var recovery: Recovery
    /// The table the keyring and public keys are kept in.
    public var table: String
    /// Remember this device: keep the master key in the Keychain (this device only) after a password
    /// unlock, so a restored session is unlocked at launch without asking for the password again.
    /// A logout removes it. Default true, as in skapi-js.
    public var persistDevice: Bool
    /// Where the remembered key is kept. Default: the Keychain, this device only.
    public var deviceKeyStorage: SkapiStorage?

    public init(iterations: Int = 600000, trustPolicy: TrustPolicy = .tofu, withheld: Withheld = .null, recovery: Recovery = .code,
                table: String = "__skapi__keyring", persistDevice: Bool = true, deviceKeyStorage: SkapiStorage? = nil) {
        self.iterations = iterations
        self.trustPolicy = trustPolicy
        self.withheld = withheld
        self.recovery = recovery
        self.table = table.isEmpty ? "__skapi__keyring" : table
        self.persistDevice = persistDevice
        self.deviceKeyStorage = deviceKeyStorage
    }

    func validate() throws {
        if iterations < 100000 { throw SkapiError("\"encryption.iterations\" must be at least 100000.", code: "INVALID_PARAMETER") }
    }
}

/// The encryption formats: constants, envelopes, recovery codes and the "SKENCF" v2 file container.
enum Enc {
    static let v = "skapi.enc.v1"
    static let envMarker = "__skapi_enc__"
    static let withheld = "__skapi_no_access__"
    static let spillLimit = 256 * 1024
    static let ctKey = "__skenc_ct__"
    static let ctFile = "payload.bin"
    static let ctFileSuffix = "/\(ctKey)/\(ctFile)"
    static let fileMarker = "__skenc__"
    static let fileChunk = 4 * 1024 * 1024
    static let envelopeCap = 2 * 1024 * 1024
    static let b62 = Array("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
    static let b32 = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")

    static func err(_ message: String, _ code: String) -> SkapiError { SkapiError(message, code: code) }

    static func isEnvelope(_ v: JSON?) -> Bool {
        guard let o = v?.object, o[envMarker]?.isNumber == true else { return false }
        return ["ct", "iv", "own", "anch"].allSatisfy { o[$0]?.isString == true } && o["k"]?.isObject == true
    }

    static func base62(_ n: Int) -> String {
        if n == 0 { return "0" }
        var v = n, out: [Character] = []
        while v > 0 { out.insert(b62[v % 62], at: 0); v /= 62 }
        return String(out)
    }

    static func fromB62Strict(_ s: String) -> Int? {
        if s.isEmpty { return nil }
        var n = 0
        for ch in s {
            guard let i = b62.firstIndex(of: ch) else { return nil }
            let (m, o1) = n.multipliedReportingOverflow(by: 62)
            let (a, o2) = m.addingReportingOverflow(i)
            if o1 || o2 { return nil }
            n = a
        }
        return n
    }

    /// "<form key>__skenc__<b62 plain size>" -> (form key, plain size), else nil.
    static func parseFileMarker(_ pathKey: String) -> (String, Int)? {
        guard let r = pathKey.range(of: fileMarker, options: .backwards) else { return nil }
        guard let size = fromB62Strict(String(pathKey[r.upperBound...])) else { return nil }
        return (String(pathKey[..<r.lowerBound]), size)
    }

    /// skapi-js's recovery code check: FNV-1a as JavaScript computes it (signed XOR, double multiply).
    static func checkBits(_ raw: Data) -> Int {
        var h: Int64 = 0x811c9dc5
        for b in raw {
            var x = h ^ Int64(b)
            if x >= 1 << 31 { x -= 1 << 32 }
            let p = (Double(x) * 16777619.0).rounded(.towardZero)
            let t = Int64(p) % (1 << 32)
            h = t < 0 ? t + (1 << 32) : t
        }
        return Int(h & 0x3ff)
    }

    static func encodeRecoveryCode(_ raw: Data) -> String {
        var out: [Character] = []
        var acc = 0, bits = 0
        for b in raw {
            acc = ((acc << 8) | Int(b)) & 0xFFFF
            bits += 8
            while bits >= 5 {
                bits -= 5
                out.append(b32[(acc >> bits) & 31])
            }
        }
        if bits > 0 { out.append(b32[(acc << (5 - bits)) & 31]) }
        let chk = checkBits(raw)
        out.append(b32[(chk >> 5) & 31])
        out.append(b32[chk & 31])
        return stride(from: 0, to: out.count, by: 4).map { String(out[$0..<min($0 + 4, out.count)]) }.joined(separator: "-")
    }

    static func decodeRecoveryCode(_ code: String) throws -> Data {
        var s = String(code.uppercased().filter { !" \t\r\n-_".contains($0) })
        s = s.replacingOccurrences(of: "O", with: "0").replacingOccurrences(of: "I", with: "1").replacingOccurrences(of: "L", with: "1")
        let chars = Array(s)
        if chars.count != 28 {
            throw err("That does not look like an encryption recovery code: expected 28 characters, got \(chars.count).", "ENCRYPTION_BAD_RECOVERY_CODE")
        }
        for ch in chars where !b32.contains(ch) {
            throw err("That does not look like an encryption recovery code: \"\(ch)\" is not a valid character.", "ENCRYPTION_BAD_RECOVERY_CODE")
        }
        var acc = 0, bits = 0
        var out = Data()
        for ch in chars[0..<26] {
            acc = ((acc << 5) | b32.firstIndex(of: ch)!) & 0xFFFF
            bits += 5
            if bits >= 8 {
                bits -= 8
                out.append(UInt8((acc >> bits) & 0xFF))
            }
        }
        let raw = Data(out.prefix(16))
        let chk = checkBits(raw)
        if String(chars[26...]) != String([b32[(chk >> 5) & 31], b32[chk & 31]]) {
            throw err("That encryption recovery code has a typo in it: the check characters do not match.", "ENCRYPTION_BAD_RECOVERY_CODE")
        }
        return raw
    }

    // ---- primitives -------------------------------------------------------------------------------

    static func hkdf(_ ikm: Data, salt: Data, info: String, length: Int = 32) -> Data {
        Prim.hkdf(ikm: ikm, salt: salt, info: utf8(info), length: length)
    }

    static func seal(_ key: Data, _ pt: Data, _ aad: Data) throws -> JSONObject {
        let iv = Prim.randomBytes(12)
        return ["iv": .string(B64.url(iv)), "ct": .string(B64.url(try Prim.aesGCMSeal(key: key, iv: iv, plaintext: pt, aad: aad)))]
    }

    static func sealRaw(_ key: Data, _ pt: Data, _ aad: Data) throws -> (Data, Data) {
        let iv = Prim.randomBytes(12)
        return (iv, try Prim.aesGCMSeal(key: key, iv: iv, plaintext: pt, aad: aad))
    }

    static func open(_ key: Data, _ iv: Data, _ ct: Data, _ aad: Data) throws -> Data {
        try Prim.aesGCMOpen(key: key, iv: iv, ciphertext: ct, aad: aad)
    }

    static func passwordKek(_ password: String, salt: Data, iterations: Int, info: String) -> Data {
        let prk = Prim.pbkdf2SHA256(password: utf8(password.precomposedStringWithCanonicalMapping), salt: salt, iterations: iterations)
        return hkdf(prk, salt: salt, info: info)
    }

    static func fingerprint(_ pubRaw: Data) -> String { B64.url(Prim.sha256(pubRaw)) }

    static func ecdhWrap(_ dek: Data, peerPub: Data, info: String, aad: Data) throws -> JSONObject {
        let (eph, epk, _) = Prim.newIdentity()
        let z = try Prim.ecdh(eph, peerPub)
        let kw = hkdf(z, salt: Data(count: 32), info: info)
        var out: JSONObject = ["epk": .string(B64.url(epk))]
        for (k, v) in try seal(kw, dek, aad) { out[k] = v }
        return out
    }

    static func ecdhUnwrap(_ priv: Prim.ECPrivateKey, _ wrap: JSONObject, info: String, aad: Data) throws -> Data {
        let z = try Prim.ecdh(priv, try B64.urlDecode(wrap["epk"]?.string))
        return try open(hkdf(z, salt: Data(count: 32), info: info), try B64.urlDecode(wrap["iv"]?.string), try B64.urlDecode(wrap["ct"]?.string), aad)
    }

    // ---- encrypted file container "SKENCF" v2 -------------------------------------------------------

    static func dekId(_ dek: Data) -> Data { Prim.sha256(utf8("\(v)|dekid") + dek).prefix(8) }

    struct FileContext {
        let service: String, owner: String, recordOwner: String, recordId: String
    }

    static func fileKey(_ dek: Data, _ fileId: Data, _ ctx: FileContext) -> Data {
        hkdf(dek, salt: fileId, info: "\(v)|binfile|\(ctx.service)|\(ctx.owner)|\(ctx.recordOwner)|\(ctx.recordId)")
    }

    static func chunkAAD(_ headerHash: String, _ i: Int, _ count: Int) -> Data {
        utf8(JSON.array([.string("\(v)|binchunk"), .string(headerHash), .number(Double(i)), .number(Double(count))]).jsonString)
    }

    static func encryptFile(dek: Data, ctx: FileContext, content: Data, name: String, contentType: String?, lastModified: Int = 0) throws -> Data {
        let meta = utf8(JSON.object(["n": .string(name), "t": .string(contentType ?? ""), "lm": .number(Double(lastModified))]).jsonString)
        if meta.count > 4096 { throw err("Encrypted file metadata is too large.", "INVALID_PARAMETER") }
        let count = max(1, (content.count + fileChunk - 1) / fileChunk)
        let fileId = Prim.randomBytes(16)
        var header = Data("SKENCF".utf8)
        header += Data([2, meta.isEmpty ? 0 : 1])
        header += Data.be(UInt64(fileChunk), 4) + Data.be(UInt64(count), 4) + fileId
        header += Data.be(UInt64(content.count), 8) + dekId(dek) + Data.be(UInt64(meta.count), 4) + Data([0, 0, 0, 0]) + meta
        let headerHash = B64.url(Prim.sha256(header))
        let key = fileKey(dek, fileId, ctx)
        var out = header
        let bytes = [UInt8](content)
        for i in 0..<count {
            let chunk = Data(bytes[min(i * fileChunk, bytes.count)..<min((i + 1) * fileChunk, bytes.count)])
            let (iv, ct) = try sealRaw(key, chunk, chunkAAD(headerHash, i, count))
            out += Data.be(UInt64(12 + ct.count), 4) + iv + ct
        }
        return out
    }

    static func isEncryptedFile(_ b: Data) -> Bool { b.count >= 56 && b.prefix(6) == Data("SKENCF".utf8) }

    static func decryptFile(dek: Data, ctx: FileContext, blob blobIn: Data) throws -> (Data, JSONObject) {
        let blob = Data(blobIn)
        if blob.count < 56 { throw err("Encrypted file header is truncated.", "INVALID_REQUEST") }
        let version = blob[6]
        let chunkSize = blob.uint(at: 8, 4)
        let count = Int(blob.uint(at: 12, 4))
        let fileId = blob.subdata(in: 16..<32)
        let plainLen = Int(blob.uint(at: 32, 8))
        let did = blob.subdata(in: 40..<48)
        let metaLen = Int(blob.uint(at: 48, 4))
        if blob.count < 56 + metaLen { throw err("Encrypted file header is truncated.", "INVALID_REQUEST") }
        let header = blob.subdata(in: 0..<(56 + metaLen))
        let meta = metaLen > 0 ? ((try? JSON.parse(utf8Decode(blob.subdata(in: 56..<(56 + metaLen)))))?.object ?? JSONObject()) : JSONObject()
        if version != 2 { throw err("This file was encrypted by a different version of the SDK (container v\(version)).", "NOT_SUPPORTED") }
        if count == 0 || chunkSize == 0 { throw err("Encrypted file header is malformed.", "INVALID_PARAMETER") }
        if did != dekId(dek) {
            throw err("This file was encrypted under a previous data key for this record, so it can no longer be opened. " +
                      "It was most likely left behind by an interrupted access change.", "ENCRYPTION_FILE_STALE_KEY")
        }
        let headerHash = B64.url(Prim.sha256(header))
        let key = fileKey(dek, fileId, ctx)
        var pos = 56 + metaLen
        var out = Data()
        for i in 0..<count {
            if pos + 4 > blob.count { throw err("Encrypted file is truncated.", "INVALID_REQUEST") }
            let n = Int(blob.uint(at: pos, 4))
            if pos + 4 + n > blob.count || n < 12 { throw err("Encrypted file is truncated.", "INVALID_REQUEST") }
            let iv = blob.subdata(in: (pos + 4)..<(pos + 16))
            let ct = blob.subdata(in: (pos + 16)..<(pos + 4 + n))
            out += try open(key, iv, ct, chunkAAD(headerHash, i, count))
            pos += 4 + n
        }
        return (out.prefix(plainLen), meta)
    }
}

/// A record's data key, as this session holds it.
struct DekEntry {
    var bytes: Data
    var recipients: JSONObject
    var anch: String
    var uid: String
    var rid: String = ""
    var own: String
    var accessGroup: JSON = "private"
    var ctURL: String = ""
    var ctStale: [String] = []
}

/// What maybeEncrypt decided for one write.
struct EncResult {
    var send: JSON = .null
    var omit = false
    var encrypted = false
    var plain: JSON?
    var dek: DekEntry?
    var spill: Data?
    var retire: [String]?
    var files: String?
    var recipients: [String] = []
}

struct DecryptContext {
    var accessGroup: JSON
    var tableName: String
    var userId: String
    var recordId: String
    var uniqueId: String?
    var ctURL: String?
    var ctURLs: [String]
}

/// Per-instance encryption state.
final class EncState {
    let cfg: EncryptionOptions
    var status = "locked"
    var reason = "NO_SESSION_KEY"
    var mk: Data?
    var ikPriv: Prim.ECPrivateKey?
    var pubRaw: Data?
    var fpr = ""
    var keyringRecordId = ""
    var userId = ""
    var pins: [String: String] = [:]
    var peerPub: [String: (Data, String)] = [:]
    var deks: [String: DekEntry] = [:]
    var passthrough: [String: JSON] = [:]
    var roll: Set<String> = []
    var rollKey: [String: Data] = [:]  // the key a revoke minted ahead of its roll
    var pendingRecoveryCode: String?
    var pendingRecoveryUser = ""
    var ready: Task<Void, Never>?  // an unlock from the device store, at launch
    var gen = 0

    init(_ cfg: EncryptionOptions) { self.cfg = cfg }

    /// Drops every key. keepRecovery is lockEncryption()'s: an encryption recovery code the app has
    /// not collected yet can never be shown again, so a lock keeps it; a logout drops it.
    func clear(keepRecovery: Bool = false) {
        gen += 1
        status = "locked"
        reason = "NO_SESSION_KEY"
        mk = nil
        ikPriv = nil
        pubRaw = nil
        fpr = ""
        keyringRecordId = ""
        userId = ""
        pins = [:]
        peerPub = [:]
        deks = [:]
        passthrough = [:]
        roll = []
        rollKey = [:]
        ready = nil
        if !keepRecovery {
            pendingRecoveryCode = nil
            pendingRecoveryUser = ""
        }
    }
}
