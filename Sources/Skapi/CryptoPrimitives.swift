import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
#if canImport(CommonCrypto)
import CommonCrypto
#endif

/// The cryptographic building blocks, on CryptoKit (Apple platforms) or swift-crypto (Linux),
/// which share one API. Everything here gives the same bytes as WebCrypto in skapi-js and the
/// `cryptography` package in skapi-py.
enum Prim {
    static func randomBytes(_ n: Int) -> Data {
        var g = SystemRandomNumberGenerator()
        var d = Data(count: n)
        for i in 0..<n { d[i] = UInt8.random(in: 0...255, using: &g) }
        return d
    }

    static func sha256(_ d: Data) -> Data { Data(SHA256.hash(data: d)) }

    static func md5Hex(_ s: String) -> String {
        Insecure.MD5.hash(data: Data(s.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    static func hmacSHA256(key: Data, _ message: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key)))
    }

    /// HKDF-SHA256 (RFC 5869).
    static func hkdf(ikm: Data, salt: Data, info: Data, length: Int = 32) -> Data {
        let prk = hmacSHA256(key: salt.isEmpty ? Data(count: 32) : salt, ikm)
        var okm = Data(), t = Data()
        var counter: UInt8 = 1
        while okm.count < length {
            t = hmacSHA256(key: prk, t + info + Data([counter]))
            okm += t
            counter &+= 1
        }
        return okm.prefix(length)
    }

    /// PBKDF2-HMAC-SHA256.
    static func pbkdf2SHA256(password: Data, salt: Data, iterations: Int, length: Int = 32) -> Data {
        #if canImport(CommonCrypto)
        var out = Data(count: length)
        let status = out.withUnsafeMutableBytes { outPtr -> Int32 in
            password.withUnsafeBytes { pwPtr -> Int32 in
                salt.withUnsafeBytes { saltPtr -> Int32 in
                    CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                         pwPtr.baseAddress?.assumingMemoryBound(to: Int8.self), password.count,
                                         saltPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), salt.count,
                                         CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), UInt32(iterations),
                                         outPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), length)
                }
            }
        }
        if status == 0 { return out }
        #endif
        let key = SymmetricKey(data: password)
        var out = Data()
        var block: UInt32 = 1
        while out.count < length {
            var u = [UInt8](HMAC<SHA256>.authenticationCode(for: salt + Data.be(UInt64(block), 4), using: key))
            var t = u
            if iterations > 1 {
                for _ in 1..<iterations {
                    u = [UInt8](HMAC<SHA256>.authenticationCode(for: u, using: key))
                    for j in 0..<t.count { t[j] ^= u[j] }
                }
            }
            out += t
            block += 1
        }
        return out.prefix(length)
    }

    // ---- AES-256-GCM: the ciphertext carries its 16-byte tag at the end (WebCrypto layout) -----

    static func aesGCMSeal(key: Data, iv: Data, plaintext: Data, aad: Data) throws -> Data {
        let box = try AES.GCM.seal(plaintext, using: SymmetricKey(data: key), nonce: AES.GCM.Nonce(data: iv), authenticating: aad)
        return box.ciphertext + box.tag
    }

    static func aesGCMOpen(key: Data, iv: Data, ciphertext: Data, aad: Data) throws -> Data {
        guard ciphertext.count >= 16 else { throw SkapiError("Ciphertext is too short.", code: "INVALID_REQUEST") }
        let ct = ciphertext.prefix(ciphertext.count - 16), tag = ciphertext.suffix(16)
        let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: iv), ciphertext: ct, tag: tag)
        return try AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: aad)
    }

    // ---- ECDH P-256 --------------------------------------------------------------------------

    typealias ECPrivateKey = P256.KeyAgreement.PrivateKey

    /// A new identity: (private key, 65-byte uncompressed public key, PKCS#8 DER private key).
    static func newIdentity() -> (ECPrivateKey, Data, Data) {
        let k = P256.KeyAgreement.PrivateKey()
        return (k, k.publicKey.x963Representation, k.derRepresentation)
    }

    static func loadPKCS8(_ der: Data) throws -> ECPrivateKey {
        try P256.KeyAgreement.PrivateKey(derRepresentation: der)
    }

    static func publicKey(_ raw: Data) throws -> P256.KeyAgreement.PublicKey {
        guard raw.count == 65, raw.first == 0x04 else {
            throw SkapiError("Malformed public key: expected a 65 byte uncompressed P-256 point.", code: "INVALID_PARAMETER")
        }
        return try P256.KeyAgreement.PublicKey(x963Representation: raw)
    }

    static func ecdh(_ priv: ECPrivateKey, _ peerRaw: Data) throws -> Data {
        let secret = try priv.sharedSecretFromKeyAgreement(with: publicKey(peerRaw))
        return secret.withUnsafeBytes { Data($0) }
    }
}

// ---- encodings ------------------------------------------------------------------------------------

enum B64 {
    /// base64url without padding.
    static func url(_ d: Data) -> String {
        d.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func urlDecode(_ s: String?) throws -> Data {
        guard let s = s else { throw SkapiError("Expected a base64url string.", code: "INVALID_PARAMETER") }
        if s.count % 4 == 1 { throw SkapiError("Malformed base64url string.", code: "INVALID_PARAMETER") }
        var t = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        t += String(repeating: "=", count: (4 - t.count % 4) % 4)
        guard let d = Data(base64Encoded: t) else { throw SkapiError("Malformed base64url string.", code: "INVALID_PARAMETER") }
        return d
    }

    /// Standard or URL-safe alphabet, padding optional, read up to the first "=" (as Node's Buffer reads it).
    static func any(_ text: String) -> Data {
        var t = String(text.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false).first ?? "")
        t = t.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        t = String(t.filter { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "+" || $0 == "/") })
        if t.count % 4 == 1 { t.removeLast() }
        t += String(repeating: "=", count: (4 - t.count % 4) % 4)
        return Data(base64Encoded: t) ?? Data()
    }
}

extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }

    /// Big-endian unsigned integer of the first `n` bytes from `at`.
    func uint(at: Int, _ n: Int) -> UInt64 {
        var v: UInt64 = 0
        for i in 0..<n { v = (v << 8) | UInt64(self[self.startIndex + at + i]) }
        return v
    }

    static func be(_ v: UInt64, _ n: Int) -> Data {
        var d = Data(count: n)
        for i in 0..<n { d[i] = UInt8((v >> UInt64(8 * (n - 1 - i))) & 0xFF) }
        return d
    }
}

/// UTF-8 bytes of a string (Swift strings hold no lone surrogates, so this is what TextEncoder writes).
func utf8(_ s: String) -> Data { Data(s.utf8) }

/// UTF-8 text of bytes, invalid sequences as U+FFFD, a leading byte order mark dropped (TextDecoder).
func utf8Decode(_ d: Data) -> String {
    let s = String(decoding: d, as: UTF8.self)
    return s.hasPrefix("\u{FEFF}") ? String(s.dropFirst()) : s
}
