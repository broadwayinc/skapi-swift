import Foundation

/// Project IDs: the compact form shown on skapi.com, and the service id and owner id inside it.
enum ProjectID {
    static let base62 = Array("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
    static let regionAlphabet = Array("0123456789abcdefghijkl")  // 22 characters, not base62 order past the digits
    static let regionKeys = ["us31", "us72", "ap51", "ap22", "ap41", "eu71", "ap21", "us32", "us71",
                             "af51", "ap31", "ap43", "ap23", "ap42", "ca01", "eu01", "eu72", "eu51",
                             "eu73", "eu11", "me51", "sa31"]

    static func isUUID(_ s: String) -> Bool {
        let parts = s.split(separator: "-", omittingEmptySubsequences: false)
        guard parts.count == 5, parts.map({ $0.count }) == [8, 4, 4, 4, 12] else { return false }
        return parts.allSatisfy { $0.allSatisfy { $0.isHexDigit && $0.isASCII } }
    }

    /// Base62 text to a 128-bit value (as two halves), for the owner UUID.
    private static func b62ToHex32(_ text: Substring) throws -> String {
        var limbs = [UInt32](repeating: 0, count: 5)  // little endian, room for overflow
        for ch in text {
            guard let d = base62.firstIndex(of: ch) else { throw paramError("Project ID is invalid.") }
            var carry = UInt64(d)
            for j in 0..<limbs.count {
                let v = UInt64(limbs[j]) * 62 + carry
                limbs[j] = UInt32(truncatingIfNeeded: v)
                carry = v >> 32
            }
        }
        if limbs[4] != 0 { throw paramError("Project ID is invalid.") }
        return limbs[0..<4].reversed().map { String(format: "%08x", $0) }.joined()
    }

    private static func hexToB62(_ hex: String) -> String {
        var limbs: [UInt32] = []
        var h = hex
        while h.count % 8 != 0 { h = "0" + h }
        var idx = h.startIndex
        while idx < h.endIndex {
            let next = h.index(idx, offsetBy: 8)
            limbs.insert(UInt32(h[idx..<next], radix: 16) ?? 0, at: 0)
            idx = next
        }
        var out: [Character] = []
        while limbs.contains(where: { $0 != 0 }) {
            var rem: UInt64 = 0
            for j in stride(from: limbs.count - 1, through: 0, by: -1) {
                let cur = (rem << 32) | UInt64(limbs[j])
                limbs[j] = UInt32(cur / 62)
                rem = cur % 62
            }
            out.insert(base62[Int(rem)], at: 0)
        }
        return out.isEmpty ? "0" : String(out)
    }

    private static func decompress(_ token: String) throws -> String {
        let parts = token.split(separator: "-", omittingEmptySubsequences: false)
        if parts.count != 2 { return token }
        let part1 = Array(parts[0]), part2 = parts[1]
        guard let first = part1.first, let length = base62.firstIndex(of: first) else { throw paramError("Project ID is invalid.") }
        let c = Array(part1.dropFirst())
        let cut = c.count - (length + 2)
        guard cut >= 0, length <= c.count - cut else { throw paramError("Project ID is invalid.") }
        let movedMiddle = Array(c[cut...])
        let movedFirst = Array(c[..<cut])
        let second = String(movedMiddle[..<length])
        let firstPart = String(movedMiddle[length...]) + String(movedFirst)
        let h = Array(try b62ToHex32(part2))
        let uuid = "\(String(h[0..<8]))-\(String(h[8..<12]))-\(String(h[12..<16]))-\(String(h[16..<20]))-\(String(h[20..<32]))"
        return "\(firstPart)-\(second)-\(uuid)"
    }

    /// (service, owner) from a Project ID, compact ("5g8N...-7Zd6...") or long (7 parts).
    static func decode(_ projectId: String) throws -> (service: String, owner: String) {
        do {
            let long = try decompress(projectId.trimmingCharacters(in: .whitespacesAndNewlines))
            let p = long.split(separator: "-", omittingEmptySubsequences: false).map(String.init)
            guard p.count == 7, let r = p[1].first, let ri = regionAlphabet.firstIndex(of: r), ri < regionKeys.count else {
                throw paramError("Project ID is invalid.")
            }
            let service = regionKeys[ri] + p[0] + String(p[1].dropFirst())
            let owner = p[2...].joined(separator: "-")
            guard isUUID(owner) else { throw paramError("Project ID is invalid.") }
            return (service, owner)
        } catch {
            throw paramError("Project ID is invalid.")
        }
    }

    /// The compact Project ID of a service id and owner id: the inverse of decode.
    static func format(service: String, owner: String) -> String? {
        let s = Array(service)
        guard s.count > 8, let ri = regionKeys.firstIndex(of: String(s[0..<4])) else { return nil }
        let first = Array(s[4..<(s.count - 4)])
        let second = String(regionAlphabet[ri]) + String(s[(s.count - 4)...])
        guard second.count < base62.count, first.count >= 2 else { return nil }
        let part1 = String(base62[second.count]) + String(first[2...]) + second + String(first[..<2])
        let part2 = hexToB62(owner.replacingOccurrences(of: "-", with: ""))
        return "\(part1)-\(part2)"
    }

    static func isProjectId(_ text: String) -> Bool {
        let n = text.split(separator: "-", omittingEmptySubsequences: false).count
        return n == 2 || n == 7
    }
}
