import Foundation
#if canImport(UniformTypeIdentifiers)
import UniformTypeIdentifiers
#endif

/// Validation and decoding helpers of the database methods, ported from skapi-py (_database.py).
enum DB {
    static let base62 = Array("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
    static let numberShift: Double = 4503599627370496  // 2^52: number index values are stored shifted by this
    static let conditions = ["gt", "gte", "lt", "lte", ">", ">=", "<", "<=", "=", "eq"]
    static let conditionsNE = conditions + ["!=", "ne"]
    static let specialIndex = ["$updated", "$uploaded", "$referenced_count", "$user_id"]
    static let orderBy = ["average_number", "total_number", "number_count", "average_bool", "total_bool",
                          "bool_count", "string_count", "index_name", "number_of_records"]
    static let privateKeyRefreshMargin: Double = 60  // seconds before a private access key expires at which it is no longer sent

    static func err(_ message: String, _ code: String = "INVALID_PARAMETER") -> SkapiError { SkapiError(message, code: code) }

    /// String length as JavaScript counts it (UTF-16 code units: an emoji counts 2).
    static func jsLength(_ s: String) -> Int { s.utf16.count }

    static func fromBase62(_ s: String) -> Double {
        var n: Double = 0
        for (i, ch) in s.reversed().enumerated() {
            let idx = base62.firstIndex(of: ch) ?? -1
            n += Double(idx) * pow(62, Double(i))
        }
        return n
    }

    static func toBase62(_ value: Int) -> String {
        if value == 0 { return "0" }
        var n = value, out: [Character] = []
        while n > 0 {
            out.insert(base62[n % 62], at: 0)
            n /= 62
        }
        return String(out)
    }

    static func encodeDelimiters(_ v: String) -> String {
        v.replacingOccurrences(of: "%", with: "%25").replacingOccurrences(of: "/", with: "%2F").replacingOccurrences(of: "!", with: "%21")
            .replacingOccurrences(of: "*", with: "%2A").replacingOccurrences(of: "#", with: "%23")
    }

    static func decodeDelimiters(_ v: JSON) -> JSON {
        guard let s = v.string else { return v }
        return .string(decodeDelimiters(s))
    }

    static func decodeDelimiters(_ s: String) -> String {
        let map = ["2F": "/", "21": "!", "2A": "*", "23": "#"]
        let once = Rx.sub("%(2F|21|2A|23)", s, .caseInsensitive) { g in map[g[1].uppercased()] ?? g[0] }
        return Rx.sub("%25", once, .caseInsensitive) { _ in "%" }
    }

    static func hasControl(_ s: String) -> Bool {
        s.unicodeScalars.contains { $0.value <= 0x1F || $0.value == 0x7F || $0.value == 0x10FFFF }
    }

    static func validateString(_ value: JSON?, _ field: String, allowEmpty: Bool = false, maxLength: Int = 256, escape: Bool = false,
                               noDollar: Bool = false, alphanumeric: Bool = false) throws -> String {
        guard var v = value?.string else { throw err("\"\(field)\" should be type: <string>.") }
        if alphanumeric && !v.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber) }) {
            throw err("\"\(field)\" should only contain alphanumeric characters.")
        }
        if !allowEmpty && v.isEmpty { throw err("\"\(field)\" is required.") }
        if maxLength > 0 && jsLength(v) > maxLength { throw err("\"\(field)\" should be <= \(maxLength) characters.") }
        if hasControl(v) { throw err("\"\(field)\" cannot include control characters or unsupported sentinel characters.") }
        if escape {
            v = encodeDelimiters(v)
            if maxLength > 0 && jsLength(v) > maxLength {
                throw err("\"\(field)\" should be <= \(maxLength) characters. \"/\", \"!\", \"*\", \"#\" and \"%\" count as 3 characters each.")
            }
        }
        if noDollar && v.hasPrefix("$") { throw err("\"\(field)\" cannot start with \"$\".") }
        return v
    }

    static func tableName(_ v: JSON?, _ field: String = "table.name", allowEmpty: Bool = false) throws -> String {
        try validateString(v, field, allowEmpty: allowEmpty, escape: true)
    }

    static func tagName(_ v: JSON?, _ field: String = "tag", allowEmpty: Bool = false) throws -> String {
        try validateString(v, field, allowEmpty: allowEmpty, escape: true)
    }

    static func indexName(_ v: JSON?, _ field: String = "index.name", allowEmpty: Bool = false) throws -> String {
        try validateString(v, field, allowEmpty: allowEmpty, escape: true, noDollar: true)
    }

    static func userId(_ v: JSON?, _ field: String = "User ID") throws -> String {
        guard let v = v, v.truthy else { throw err("\(field) is empty.") }
        guard let s = v.string else { throw err("\(field) should be type: string.") }
        if !Check.isUUID(s) { throw err("\(field) is invalid.") }
        return s
    }

    static func accessGroupIn(_ v: JSON?, signedIn: Bool) throws -> JSON {
        let result: JSON
        switch v {
        case .some(.number(let n)):
            if n > 99 || n < 0 { throw err("\"table.access_group\" value should be within a range of 0 ~ 99.") }
            result = .number(n)
        case .some(.string(let s)):
            let mapping: [String: JSON] = ["*": "private", "private": "private", "public": 0, "authorized": 1, "admin": 99]
            guard let m = mapping[s] else { throw err("\"table.access_group\" is invalid.") }
            result = m
        default:
            throw err("\"table.access_group\" should be type: <number | string>.")
        }
        if !signedIn && result.truthy { throw err("Unsigned users have no access to records with access group.") }
        return result
    }

    static func accessGroupOut(_ v: String) -> JSON {
        if v == "**" { return "private" }
        guard let n = Int(v) else { return .string(v) }
        switch n {
        case 0: return "public"
        case 1: return "authorized"
        case 99: return "admin"
        default: return .number(Double(n))
        }
    }

    static func indexValue(_ v: JSON?, _ field: String = "index.value") throws -> JSON {
        switch v {
        case .some(.bool): return v!
        case .some(.number(let n)):
            if abs(n) > numberShift { throw err("Number value should be within range -4503599627370496 ~ +4503599627370496") }
            return v!
        case .some(.string): return .string(try validateString(v, field, allowEmpty: true))
        default: throw err("\"\(field)\" should be type: <number | boolean | string>.")
        }
    }

    static func typeOf(_ v: JSON?) -> String {
        switch v {
        case .some(.bool): return "boolean"
        case .some(.number): return "number"
        case .some(.string): return "string"
        default: return "object"
        }
    }

    static func condition(_ v: JSON?, _ allowed: [String] = conditions, _ field: String = "condition") throws -> String {
        guard let s = v?.string, allowed.contains(s) else {
            throw err("\(jd(v)) is invalid in \"\(field)\". allowed types or values are: " + allowed.map { jd(.string($0)) }.joined(separator: ", ") + ".")
        }
        return s
    }

    /// ID mode: only service, owner and record_id (or else unique_id) survive.
    static func recordOrUniqueId(_ query: JSONObject, isDelete: Bool) throws -> JSONObject? {
        if isDelete {
            for key in ["record_id", "unique_id"] {
                if let v = query[key], !v.isNull, v == .string("") || v == .array([]) { throw err("\"\(key)\" is empty.") }
            }
        }
        if !query["record_id"].truthy && !query["unique_id"].truthy { return nil }
        var out = JSONObject()
        for key in ["service", "owner"] where query[key].truthy { out[key] = query[key] }
        let key = query["record_id"].truthy ? "record_id" : "unique_id"
        let value = query[key]!
        func one(_ v: JSON, _ field: String) throws -> JSON {
            if key == "record_id" { return .string(try validateString(v, field, maxLength: 0, alphanumeric: true)) }
            guard let s = v.string else { throw err("\"\(field)\" should be type: <string>.") }
            if s.isEmpty { throw err("\"\(field)\" is required.") }
            return v
        }
        if let list = value.array {
            if !isDelete { throw err("\"\(key)\" should be type: <string>.") }
            if list.isEmpty { throw err("\"\(key)\" should not be an empty list.") }
            if list.count > 1000 { throw err("\"\(key)\" can hold at most 1000 ids.") }
            out[key] = .array(try list.enumerated().map { try one($1, "\(key)[\($0)]") })
        } else {
            out[key] = try one(value, key)
        }
        return out
    }

    /// Index values as the server stores them ("!S%text", "!N%<number + 2^52>", "!B%1").
    static func typedString(_ v: String) throws -> JSON {
        let prefix = String(v.prefix(3)), body = String(v.dropFirst(3))
        switch prefix {
        case "!S%": return .string(body)
        case "!B%": return .bool(body == "1")
        case "!L%", "!D%":
            guard let parsed = try? JSON.parse(body) else { throw SkapiError("Value parse error.", code: "PARSE_ERROR") }
            return parsed
        case "!N%":
            let parts = body.split(separator: ".", maxSplits: 1, omittingEmptySubsequences: false).map(String.init)
            let whole = parts[0], frac = parts.count > 1 ? parts[1] : ""
            guard let w = Double(whole) else { return .string(v) }
            let n = w - numberShift
            if frac.isEmpty { return .number(n) }
            if n >= 0 || !frac.contains(where: { "123456789".contains($0) }) {
                return .number(Double("\(JSONWriter.jsNumber(n)).\(frac)") ?? n)
            }
            var digits = frac
            while digits.hasSuffix("0") { digits.removeLast() }
            let ds = Array(digits)
            var complement = ds.dropLast().map { String(9 - Int(String($0))!) }.joined()
            complement += String(10 - Int(String(ds.last!))!)
            return .number(Double("-\(JSONWriter.jsNumber(-n - 1)).\(complement)") ?? n)
        default:
            return .string(v)
        }
    }

    /// The stored record payload ("!J%<json>" and the legacy forms) as the value that was posted.
    static func parseStoredData(_ r: JSON) -> (JSON, changed: Bool) {
        if let s = r.string {
            if s.hasPrefix("!J%") { return ((try? JSON.parse(String(s.dropFirst(3)))) ?? r, true) }
            if s == "!D%{}" { return (.object(JSONObject()), true) }
            if s == "!L%[]" { return (.array([]), true) }
            return (r, true)
        }
        if let o = r.object, o.keys == ["__json__"], let s = o["__json__"]?.string {
            if let parsed = try? JSON.parse(s) { return (parsed, true) }
            return (r, false)
        }
        return (r, false)
    }

    static func isOffloadMarker(_ r: JSON?) -> Bool {
        guard let o = r?.object, o.keys == ["__data__"], let s = o["__data__"]?.string else { return false }
        return s.hasSuffix("/__data__/__json__.json")
    }

    static func randomKey(_ n: Int = 6) -> String {
        let chars = Array("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        return String((0..<n).map { _ in chars.randomElement()! })
    }

    // The ASCII bytes a URL path encoder percent-encodes (as the WHATWG URL parser skapi-js uses).
    static let urlPathEncodedASCII: Set<UInt8> = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0B, 0x0C, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x22, 0x3C, 0x3E, 0x5E, 0x60, 0x7B, 0x7D, 0x7F]

    /// Undoes only what a url path encoder produces: uppercase %XX of the bytes above and of valid
    /// UTF-8 sequences. Any other "%" is part of the file's own name and is kept.
    static func undoURLPathEncoding(_ url: String) -> String {
        Rx.sub("(?:%[0-9A-F]{2})+", url) { g in
            let run = g[0]
            var tokens: [String] = []
            var idx = run.startIndex
            while idx < run.endIndex {
                let end = run.index(idx, offsetBy: 3)
                tokens.append(String(run[idx..<end]))
                idx = end
            }
            var out = ""
            var i = 0
            while i < tokens.count {
                let b = UInt8(tokens[i].dropFirst(), radix: 16)!
                if b < 0x80 {
                    out += urlPathEncodedASCII.contains(b) ? String(UnicodeScalar(b)) : tokens[i]
                    i += 1
                    continue
                }
                let n = b >= 0xF0 ? 4 : b >= 0xE0 ? 3 : b >= 0xC0 ? 2 : 1
                if n > 1, i + n <= tokens.count {
                    let bytes = tokens[i..<(i + n)].map { UInt8($0.dropFirst(), radix: 16)! }
                    if let s = String(bytes: bytes, encoding: .utf8), s.unicodeScalars.count == 1 {
                        out += s
                        i += n
                        continue
                    }
                }
                out += tokens[i]
                i += 1
            }
            return out
        }
    }

    static func jsonBytes(_ v: JSON) -> Int { v.jsonString.utf8.count }
}

// ---- files you attach ----------------------------------------------------------------------------

/// The contents of a file to upload.
public enum FileSource: @unchecked Sendable {
    /// A local file, read when the call runs. Its name is the default filename.
    case url(URL)
    /// A path to a local file.
    case path(String)
    /// Bytes in memory (give a filename).
    case data(Data)
    /// A stream, read to its end (give a filename).
    case stream(InputStream)
}

/// One file to attach to a record, under a field name of the record's `bin`.
public struct UploadFile: Sendable {
    public var name: String
    public var file: FileSource
    public var filename: String?
    public var contentType: String?

    /// name: the field the file is listed under in the record's `bin`.
    public init(name: String, file: FileSource, filename: String? = nil, contentType: String? = nil) {
        self.name = name
        self.file = file
        self.filename = filename
        self.contentType = contentType
    }
}

struct PreparedFile {
    var name: String
    var filename: String
    var content: Data
    var contentType: String?
    var presealed = false
}

enum Mime {
    static let table: [String: String] = [
        "txt": "text/plain", "html": "text/html", "htm": "text/html", "css": "text/css", "csv": "text/csv", "js": "text/javascript",
        "json": "application/json", "xml": "application/xml", "pdf": "application/pdf", "zip": "application/zip",
        "png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "gif": "image/gif", "webp": "image/webp", "svg": "image/svg+xml",
        "heic": "image/heic", "ico": "image/vnd.microsoft.icon", "bmp": "image/bmp", "tif": "image/tiff", "tiff": "image/tiff",
        "mp3": "audio/mpeg", "m4a": "audio/mp4", "wav": "audio/x-wav", "ogg": "audio/ogg", "mp4": "video/mp4", "mov": "video/quicktime",
        "webm": "video/webm", "md": "text/markdown", "doc": "application/msword",
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls": "application/vnd.ms-excel", "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "ppt": "application/vnd.ms-powerpoint", "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ]

    /// The content type a filename's extension names, or nil.
    static func guess(_ filename: String) -> String? {
        let ext = (filename as NSString).pathExtension.lowercased()
        if ext.isEmpty { return nil }
        #if canImport(UniformTypeIdentifiers)
        if #available(iOS 14.0, macOS 11.0, *), let t = UTType(filenameExtension: ext)?.preferredMIMEType { return t }
        #endif
        return table[ext]
    }
}

func prepareFiles(_ files: [UploadFile]?) throws -> [PreparedFile] {
    var out: [PreparedFile] = []
    for (i, f) in (files ?? []).enumerated() {
        if f.name.isEmpty { throw DB.err("\"files[\(i)]\" should have a field name.") }
        var filename = f.filename
        let content: Data
        func readFile(_ url: URL) throws -> Data {
            do { return try Data(contentsOf: url) } catch {
                throw SkapiError("\"files[\(i)].file\" cannot be read: \(error.localizedDescription).", code: "INVALID_PARAMETER", cause: error)
            }
        }
        switch f.file {
        case .url(let u):
            content = try readFile(u)
            filename = filename ?? u.lastPathComponent
        case .path(let p):
            let u = URL(fileURLWithPath: (p as NSString).expandingTildeInPath)
            content = try readFile(u)
            filename = filename ?? u.lastPathComponent
        case .data(let d):
            content = d
        case .stream(let s):
            var d = Data()
            s.open()
            defer { s.close() }
            var buf = [UInt8](repeating: 0, count: 65536)
            while true {
                let n = s.read(&buf, maxLength: buf.count)
                if n < 0 {
                    throw SkapiError("\"files[\(i)].file\" cannot be read: \(s.streamError?.localizedDescription ?? "stream error").",
                                     code: "INVALID_PARAMETER", cause: s.streamError)
                }
                if n == 0 { break }
                d.append(buf, count: n)
            }
            content = d
        }
        guard let fname = filename, !fname.isEmpty else { throw DB.err("\"files[\(i)].filename\" is required for bytes.") }
        out.append(PreparedFile(name: f.name, filename: fname, content: content, contentType: f.contentType ?? Mime.guess(fname)))
    }
    return out
}
