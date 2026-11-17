import Foundation

/// A small unsigned big integer for the SRP sign-in math (3072-bit modular exponentiation).
/// Little-endian 32-bit limbs; no leading zero limbs.
struct BigUInt: Equatable, Comparable {
    private(set) var limbs: [UInt32]

    init() { limbs = [] }
    init(_ v: UInt64) {
        limbs = [UInt32(truncatingIfNeeded: v), UInt32(truncatingIfNeeded: v >> 32)]
        normalize()
    }
    private init(limbs: [UInt32]) {
        self.limbs = limbs
        normalize()
    }

    /// Hex text, as `new BigInteger(hex, 16)` reads it (empty is zero). Nil for a non-hex character.
    init?(hex: String) {
        var l: [UInt32] = []
        var chars = Array(hex.utf8)
        if chars.isEmpty { self.init(); return }
        while chars.count % 8 != 0 { chars.insert(UInt8(ascii: "0"), at: 0) }
        var i = chars.count
        while i > 0 {
            var v: UInt32 = 0
            for c in chars[(i - 8)..<i] {
                let d: UInt32
                switch c {
                case 0x30...0x39: d = UInt32(c - 0x30)
                case 0x61...0x66: d = UInt32(c - 0x61 + 10)
                case 0x41...0x46: d = UInt32(c - 0x41 + 10)
                default: return nil
                }
                v = (v << 4) | d
            }
            l.append(v)
            i -= 8
        }
        self.init(limbs: l)
    }

    /// Big-endian bytes.
    init(bytes: Data) {
        let b = [UInt8](bytes)
        var l: [UInt32] = []
        var i = b.count
        while i > 0 {
            var v: UInt32 = 0
            for c in b[max(0, i - 4)..<i] { v = (v << 8) | UInt32(c) }
            l.append(v)
            i -= 4
        }
        self.init(limbs: l)
    }

    private mutating func normalize() { while let last = limbs.last, last == 0 { limbs.removeLast() } }

    var isZero: Bool { limbs.isEmpty }

    /// Lowercase hex without leading zeros ("0" for zero).
    var hex: String {
        guard let top = limbs.last else { return "0" }
        var s = String(top, radix: 16)
        for l in limbs.dropLast().reversed() {
            let h = String(l, radix: 16)
            s += String(repeating: "0", count: 8 - h.count) + h
        }
        return s
    }

    static func < (a: BigUInt, b: BigUInt) -> Bool {
        if a.limbs.count != b.limbs.count { return a.limbs.count < b.limbs.count }
        for i in stride(from: a.limbs.count - 1, through: 0, by: -1) where a.limbs[i] != b.limbs[i] {
            return a.limbs[i] < b.limbs[i]
        }
        return false
    }

    static func + (a: BigUInt, b: BigUInt) -> BigUInt {
        var r = [UInt32](repeating: 0, count: max(a.limbs.count, b.limbs.count) + 1)
        var carry: UInt64 = 0
        for i in 0..<(r.count - 1) {
            let s = UInt64(i < a.limbs.count ? a.limbs[i] : 0) + UInt64(i < b.limbs.count ? b.limbs[i] : 0) + carry
            r[i] = UInt32(truncatingIfNeeded: s)
            carry = s >> 32
        }
        r[r.count - 1] = UInt32(carry)
        return BigUInt(limbs: r)
    }

    /// a - b, for a >= b.
    static func - (a: BigUInt, b: BigUInt) -> BigUInt {
        var r = a.limbs
        var borrow: Int64 = 0
        for i in 0..<r.count {
            var d = Int64(r[i]) - Int64(i < b.limbs.count ? b.limbs[i] : 0) - borrow
            if d < 0 { d += 1 << 32; borrow = 1 } else { borrow = 0 }
            r[i] = UInt32(d)
        }
        return BigUInt(limbs: r)
    }

    static func * (a: BigUInt, b: BigUInt) -> BigUInt {
        if a.isZero || b.isZero { return BigUInt() }
        var r = [UInt32](repeating: 0, count: a.limbs.count + b.limbs.count)
        for i in 0..<a.limbs.count {
            var carry: UInt64 = 0
            let ai = UInt64(a.limbs[i])
            for j in 0..<b.limbs.count {
                let t = ai * UInt64(b.limbs[j]) + UInt64(r[i + j]) + carry
                r[i + j] = UInt32(truncatingIfNeeded: t)
                carry = t >> 32
            }
            r[i + b.limbs.count] = UInt32(carry)
        }
        return BigUInt(limbs: r)
    }

    /// a mod m (Knuth, algorithm D).
    static func % (a: BigUInt, m: BigUInt) -> BigUInt {
        precondition(!m.isZero, "modulus is zero")
        if a < m { return a }
        if m.limbs.count == 1 {
            let d = UInt64(m.limbs[0])
            var rem: UInt64 = 0
            for l in a.limbs.reversed() { rem = ((rem << 32) | UInt64(l)) % d }
            return BigUInt(rem)
        }
        let s = UInt32(m.limbs.last!.leadingZeroBitCount)
        let v = shiftLeft(m.limbs, s)
        var u = shiftLeft(a.limbs, s)
        if u.count == a.limbs.count { u.append(0) }
        let n = v.count, mCount = u.count - n
        let vTop = UInt64(v[n - 1]), vNext = UInt64(v[n - 2])
        let base: UInt64 = 1 << 32
        for j in stride(from: mCount - 1, through: 0, by: -1) {
            let num = (UInt64(u[j + n]) << 32) | UInt64(u[j + n - 1])
            var qhat = num / vTop
            var rhat = num % vTop
            while qhat >= base || qhat * vNext > ((rhat << 32) | UInt64(u[j + n - 2])) {
                qhat -= 1
                rhat += vTop
                if rhat >= base { break }
            }
            var borrow: Int64 = 0
            var carry: UInt64 = 0
            for i in 0..<n {
                let p = qhat * UInt64(v[i]) + carry
                carry = p >> 32
                let t = Int64(u[i + j]) - borrow - Int64(p & 0xFFFF_FFFF)
                u[i + j] = UInt32(truncatingIfNeeded: t)
                borrow = t < 0 ? 1 : 0
            }
            let t = Int64(u[j + n]) - borrow - Int64(carry)
            u[j + n] = UInt32(truncatingIfNeeded: t)
            if t < 0 {
                var c: UInt64 = 0
                for i in 0..<n {
                    let sum = UInt64(u[i + j]) + UInt64(v[i]) + c
                    u[i + j] = UInt32(truncatingIfNeeded: sum)
                    c = sum >> 32
                }
                u[j + n] = UInt32(truncatingIfNeeded: UInt64(u[j + n]) + c)
            }
        }
        return BigUInt(limbs: shiftRight(Array(u[0..<n]), s))
    }

    private static func shiftLeft(_ x: [UInt32], _ s: UInt32) -> [UInt32] {
        if s == 0 { return x }
        var r = [UInt32](repeating: 0, count: x.count + 1)
        for i in 0..<x.count {
            r[i] |= x[i] << s
            r[i + 1] = x[i] >> (32 - s)
        }
        if r.last == 0 { r.removeLast() }
        return r
    }

    private static func shiftRight(_ x: [UInt32], _ s: UInt32) -> [UInt32] {
        if s == 0 { return x }
        var r = [UInt32](repeating: 0, count: x.count)
        for i in 0..<x.count {
            r[i] = x[i] >> s
            if i + 1 < x.count { r[i] |= x[i + 1] << (32 - s) }
        }
        return r
    }

    private var bitWidth: Int { limbs.isEmpty ? 0 : limbs.count * 32 - limbs.last!.leadingZeroBitCount }
    private func bit(_ i: Int) -> Bool { (limbs[i / 32] >> UInt32(i % 32)) & 1 == 1 }

    /// base^exp mod m.
    static func modPow(_ base: BigUInt, _ exp: BigUInt, _ m: BigUInt) -> BigUInt {
        var result = BigUInt(1) % m
        let b = base % m
        if exp.isZero { return result }
        for i in stride(from: exp.bitWidth - 1, through: 0, by: -1) {
            result = (result * result) % m
            if exp.bit(i) { result = (result * b) % m }
        }
        return result
    }
}
