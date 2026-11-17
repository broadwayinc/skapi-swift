import Foundation

/// Cognito's SRP-6a password sign-in, ported from skapi-py (_srp.py), itself a port of skapi-js
/// (src/cognito/srp.ts). Every step, padHex in particular, gives the same bytes: a wrong padding
/// fails a sign-in only when a value starts with a high bit, about 1 in 256 attempts.
///
/// The password never leaves the device: only A (g^a mod N) and a signature made with the derived
/// key are sent.
enum SRP {
    static let nHex =
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" + "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D" + "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" + "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
        "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" + "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
        "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" + "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
        "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" + "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"

    static let N = BigUInt(hex: nHex)!
    static let G = BigUInt(2)
    static let K = hexToInt(hexHash(padHex(N) + padHex(G)))
    static let infoBits = utf8("Caldera Derived Key") + Data([0x01])

    /// Hex to integer, as `new BigInteger(hex, 16)` reads it (an empty string is 0).
    static func hexToInt(_ hex: String) -> BigUInt { BigUInt(hex: hex) ?? BigUInt() }

    /// Two characters at a time, stopping at the first pair that is not hex (Buffer.from(hex, 'hex')).
    static func hexToBytes(_ hex: String) -> Data {
        let c = Array(hex.utf8)
        var out = Data()
        var i = 0
        while i + 1 < c.count {
            guard let v = UInt8(String(decoding: c[i...(i + 1)], as: UTF8.self), radix: 16) else { break }
            out.append(v)
            i += 2
        }
        return out
    }

    /// Signed big-endian hex exactly as the library writes it for a non-negative value: even length,
    /// and a leading "00" when the top bit is set (so the value stays positive).
    static func padHex(_ v: BigUInt) -> String {
        var h = v.hex
        if h.count % 2 == 1 { h = "0" + h }
        if let f = h.first, "89abcdefABCDEF".contains(f) { h = "00" + h }
        return h
    }

    static func hashHex(_ d: Data) -> String { Prim.sha256(d).hex }
    static func hexHash(_ hex: String) -> String { hashHex(hexToBytes(hex)) }

    /// HKDF-SHA256 with Cognito's info string, first 16 bytes.
    static func computeHKDF(ikm: Data, salt: Data) -> Data {
        let prk = Prim.hmacSHA256(key: salt, ikm)
        return Prim.hmacSHA256(key: prk, infoBits).prefix(16)
    }

    struct Helper {
        let poolName: String
        let smallA: BigUInt
        let largeA: BigUInt

        /// poolName: the part of the user pool id after the underscore.
        /// smallA: for the equivalence checks only, a fixed secret instead of 128 random bytes.
        init(poolName: String, smallA: BigUInt? = nil) throws {
            self.poolName = poolName
            // 128 random bytes read as a positive integer; no reduction needed, N is 3072 bits.
            self.smallA = smallA ?? BigUInt(bytes: Prim.randomBytes(128))
            self.largeA = BigUInt.modPow(SRP.G, self.smallA, SRP.N)
            if (largeA % SRP.N).isZero { throw SkapiError("Illegal paramater. A mod N cannot be 0.", code: "ERROR") }
        }

        /// The 16 byte key both sides derive; Cognito checks a signature made with it.
        func passwordAuthenticationKey(username: String, password: String, serverB: BigUInt, salt: BigUInt) throws -> Data {
            if (serverB % SRP.N).isZero { throw SkapiError("B cannot be zero.", code: "ERROR") }
            let u = SRP.hexToInt(SRP.hexHash(SRP.padHex(largeA) + SRP.padHex(serverB)))
            if u.isZero { throw SkapiError("U cannot be zero.", code: "ERROR") }
            let userPassHash = SRP.hashHex(utf8("\(poolName)\(username):\(password)"))
            let x = SRP.hexToInt(SRP.hexHash(SRP.padHex(salt) + userPassHash))
            // S = (B - k * g^x) ^ (a + u * x) mod N, with the base taken as its residue in [0, N)
            let kgx = (SRP.K * BigUInt.modPow(SRP.G, x, SRP.N)) % SRP.N
            let b = serverB % SRP.N
            let base = b < kgx ? (b + SRP.N) - kgx : b - kgx
            let s = BigUInt.modPow(base, smallA + u * x, SRP.N)
            return SRP.computeHKDF(ikm: SRP.hexToBytes(SRP.padHex(s)), salt: SRP.hexToBytes(SRP.padHex(u)))
        }
    }

    /// "Sun Nov 15 16:52:00 UTC 2026": the day is not zero padded, the time is.
    static func cognitoTimestamp(_ date: Date = Date()) -> String {
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = TimeZone(identifier: "UTC")!
        let c = cal.dateComponents([.weekday, .month, .day, .hour, .minute, .second, .year], from: date)
        let week = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
        let month = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
        return "\(week[c.weekday! - 1]) \(month[c.month! - 1]) \(c.day!) " +
            String(format: "%02d:%02d:%02d", c.hour!, c.minute!, c.second!) + " UTC \(c.year!)"
    }

    /// The PASSWORD_CLAIM_SIGNATURE: base64 of HMAC-SHA256(key, poolName + username + secretBlock + timestamp).
    static func signature(key: Data, poolName: String, username: String, secretBlock: String, timestamp: String) -> String {
        let message = utf8(poolName) + utf8(username) + B64.any(secretBlock) + utf8(timestamp)
        return Prim.hmacSHA256(key: key, message).base64EncodedString()
    }
}
