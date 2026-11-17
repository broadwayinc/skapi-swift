import Foundation

/// The MD5 skapi-js uses to name accounts ("<service>-<md5(e-mail or username)>"), ported literally.
///
/// It works on UTF-16 code units, not UTF-8 bytes: for ASCII it equals standard MD5, for
/// U+0080..U+00FF it equals MD5 of the latin-1 bytes, and above U+00FF it gives digests no standard
/// MD5 produces. A username must hash exactly as skapi-js hashes it, or that account cannot sign in.
enum MD5JS {
    private typealias Step = (k: Int, s: UInt32, t: Int64)

    private static let rounds: [[Step]] = [
        [(0, 7, -680876936), (1, 12, -389564586), (2, 17, 606105819), (3, 22, -1044525330), (4, 7, -176418897), (5, 12, 1200080426),
         (6, 17, -1473231341), (7, 22, -45705983), (8, 7, 1770035416), (9, 12, -1958414417), (10, 17, -42063), (11, 22, -1990404162),
         (12, 7, 1804603682), (13, 12, -40341101), (14, 17, -1502002290), (15, 22, 1236535329)],
        [(1, 5, -165796510), (6, 9, -1069501632), (11, 14, 643717713), (0, 20, -373897302), (5, 5, -701558691), (10, 9, 38016083),
         (15, 14, -660478335), (4, 20, -405537848), (9, 5, 568446438), (14, 9, -1019803690), (3, 14, -187363961), (8, 20, 1163531501),
         (13, 5, -1444681467), (2, 9, -51403784), (7, 14, 1735328473), (12, 20, -1926607734)],
        [(5, 4, -378558), (8, 11, -2022574463), (11, 16, 1839030562), (14, 23, -35309556), (1, 4, -1530992060), (4, 11, 1272893353),
         (7, 16, -155497632), (10, 23, -1094730640), (13, 4, 681279174), (0, 11, -358537222), (3, 16, -722521979), (6, 23, 76029189),
         (9, 4, -640364487), (12, 11, -421815835), (15, 16, 530742520), (2, 23, -995338651)],
        [(0, 6, -198630844), (7, 10, 1126891415), (14, 15, -1416354905), (5, 21, -57434055), (12, 6, 1700485571), (3, 10, -1894986606),
         (10, 15, -1051523), (1, 21, -2054922799), (8, 6, 1873313359), (15, 10, -30611744), (6, 15, -1560198380), (13, 21, 1309151649),
         (4, 6, -145523070), (11, 10, -1120210379), (2, 15, 718787259), (9, 21, -343485551)],
    ]

    private static func rl(_ n: UInt32, _ c: UInt32) -> UInt32 { (n << c) | (n >> (32 - c)) }
    private static func cm(_ q: UInt32, _ a: UInt32, _ b: UInt32, _ x: UInt32, _ s: UInt32, _ t: UInt32) -> UInt32 {
        rl(a &+ q &+ (x &+ t), s) &+ b
    }
    private static func f(_ r: Int, _ b: UInt32, _ c: UInt32, _ d: UInt32) -> UInt32 {
        switch r {
        case 0: return (b & c) | (~b & d)
        case 1: return (b & d) | (c & ~d)
        case 2: return b ^ c ^ d
        default: return c ^ (b | ~d)
        }
    }

    static func hash(_ text: String) -> String {
        let codes = Array(text.utf16)
        let length = codes.count
        let numBlocks = ((length + 8) >> 6) + 1
        var x = [UInt32](repeating: 0, count: numBlocks * 16)
        for (i, cu) in codes.enumerated() {
            x[i >> 2] |= UInt32(truncatingIfNeeded: UInt64(cu) << UInt64((i % 4) * 8))
        }
        x[length >> 2] |= UInt32(truncatingIfNeeded: UInt64(0x80) << UInt64((length % 4) * 8))
        x[numBlocks * 16 - 2] = UInt32(truncatingIfNeeded: length * 8)

        var a: UInt32 = 1732584193, b = UInt32(bitPattern: -271733879), c = UInt32(bitPattern: -1732584194), d: UInt32 = 271733878
        var i = 0
        while i < x.count {
            let la = a, lb = b, lc = c, ld = d
            for (r, steps) in rounds.enumerated() {
                for (n, st) in steps.enumerated() {
                    let t = UInt32(truncatingIfNeeded: st.t)
                    let xv = x[i + st.k]
                    switch n % 4 {
                    case 0: a = cm(f(r, b, c, d), a, b, xv, st.s, t)
                    case 1: d = cm(f(r, a, b, c), d, a, xv, st.s, t)
                    case 2: c = cm(f(r, d, a, b), c, d, xv, st.s, t)
                    default: b = cm(f(r, c, d, a), b, c, xv, st.s, t)
                    }
                }
            }
            a = a &+ la; b = b &+ lb; c = c &+ lc; d = d &+ ld
            i += 16
        }
        let hex = Array("0123456789abcdef")
        func rh(_ n: UInt32) -> String {
            var s = ""
            for j in 0..<4 {
                s.append(hex[Int((n >> UInt32(j * 8 + 4)) & 0x0F)])
                s.append(hex[Int((n >> UInt32(j * 8)) & 0x0F)])
            }
            return s
        }
        return rh(a) + rh(b) + rh(c) + rh(d)
    }
}
