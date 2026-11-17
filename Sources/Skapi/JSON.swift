import Foundation

/// A JSON value: what record data, queries, configs and answers are made of.
///
/// Objects keep their keys in the order they were written, the way JavaScript objects do, so a
/// value written here serializes the same way skapi-js would write it. Numbers are doubles, as in
/// JavaScript; `int` reads one back as an integer.
///
/// ```swift
/// let data: JSON = ["title": "Hello", "tags": ["a", "b"], "views": 0]
/// data["title"]?.string    // "Hello"
/// ```
public enum JSON: Sendable, Hashable {
    case null
    case bool(Bool)
    case number(Double)
    case string(String)
    case array([JSON])
    case object(JSONObject)

    // ---- reading ----------------------------------------------------------------------------

    public var string: String? { if case .string(let s) = self { return s }; return nil }
    public var bool: Bool? { if case .bool(let b) = self { return b }; return nil }
    public var number: Double? { if case .number(let n) = self { return n }; return nil }
    public var array: [JSON]? { if case .array(let a) = self { return a }; return nil }
    public var object: JSONObject? { if case .object(let o) = self { return o }; return nil }
    public var isNull: Bool { if case .null = self { return true }; return false }

    /// The number as an integer, when it is one (and fits).
    public var int: Int? {
        guard case .number(let n) = self, n.isFinite, n == n.rounded(), abs(n) < 9.2e18 else { return nil }
        return Int(n)
    }

    /// A member of an object (nil when missing or when this is not an object).
    public subscript(key: String) -> JSON? {
        get { object?[key] }
        set {
            guard case .object(var o) = self else { return }
            o[key] = newValue
            self = .object(o)
        }
    }

    /// An element of an array (nil when out of range or when this is not an array).
    public subscript(index: Int) -> JSON? {
        guard case .array(let a) = self, index >= 0, index < a.count else { return nil }
        return a[index]
    }

    // ---- serialization ------------------------------------------------------------------------

    /// Compact JSON text, as JavaScript's JSON.stringify writes it.
    public var jsonString: String {
        var out = ""
        JSONWriter.write(self, into: &out, asciiOnly: false)
        return out
    }

    /// Parses JSON text. Object keys keep their order.
    public static func parse(_ text: String) throws -> JSON {
        var parser = JSONParser(Array(text.utf8))
        return try parser.parseDocument()
    }

    /// Parses JSON bytes (UTF-8). Object keys keep their order.
    public static func parse(_ data: Data) throws -> JSON {
        var parser = JSONParser(Array(data))
        return try parser.parseDocument()
    }

    // ---- Codable bridging ---------------------------------------------------------------------

    /// A JSON value from any Encodable value (through JSONEncoder).
    public init<T: Encodable>(encoding value: T) throws {
        let data = try JSONEncoder().encode(value)
        self = try JSON.parse(data)
    }

    /// Decodes this value into a Decodable type (through JSONDecoder).
    public func decode<T: Decodable>(_ type: T.Type, decoder: JSONDecoder = JSONDecoder()) throws -> T {
        try decoder.decode(T.self, from: Data(jsonString.utf8))
    }
}

extension JSON: ExpressibleByNilLiteral, ExpressibleByBooleanLiteral, ExpressibleByIntegerLiteral,
                ExpressibleByFloatLiteral, ExpressibleByStringLiteral, ExpressibleByArrayLiteral,
                ExpressibleByDictionaryLiteral {
    public init(nilLiteral: ()) { self = .null }
    public init(booleanLiteral value: Bool) { self = .bool(value) }
    public init(integerLiteral value: Int) { self = .number(Double(value)) }
    public init(floatLiteral value: Double) { self = .number(value) }
    public init(stringLiteral value: String) { self = .string(value) }
    public init(arrayLiteral elements: JSON...) { self = .array(elements) }
    public init(dictionaryLiteral elements: (String, JSON)...) {
        var o = JSONObject()
        for (k, v) in elements { o[k] = v }
        self = .object(o)
    }
}

extension JSON {
    public init(_ value: String) { self = .string(value) }
    public init(_ value: Bool) { self = .bool(value) }
    public init(_ value: Int) { self = .number(Double(value)) }
    public init(_ value: Double) { self = .number(value) }
    public init(_ value: [JSON]) { self = .array(value) }
    public init(_ value: JSONObject) { self = .object(value) }
    public init(_ value: [String: JSON]) {
        var o = JSONObject()
        for k in value.keys.sorted() { o[k] = value[k] }
        self = .object(o)
    }
    public init(_ value: String?) { self = value.map { .string($0) } ?? .null }
}

extension JSON: CustomStringConvertible {
    public var description: String { jsonString }
}

extension JSON: Codable {
    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null }
        else if let b = try? c.decode(Bool.self) { self = .bool(b) }
        else if let n = try? c.decode(Double.self) { self = .number(n) }
        else if let s = try? c.decode(String.self) { self = .string(s) }
        else if let a = try? c.decode([JSON].self) { self = .array(a) }
        else if let o = try? c.decode([String: JSON].self) { self = JSON(o) }
        else { throw DecodingError.dataCorruptedError(in: c, debugDescription: "Not a JSON value.") }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .null: try c.encodeNil()
        case .bool(let b): try c.encode(b)
        case .number(let n): try c.encode(n)
        case .string(let s): try c.encode(s)
        case .array(let a): try c.encode(a)
        case .object(let o): try c.encode(o.dictionary)
        }
    }
}

/// A JSON object whose keys keep their insertion order.
public struct JSONObject: Sendable, Hashable, Sequence, ExpressibleByDictionaryLiteral {
    public private(set) var keys: [String] = []
    private var storage: [String: JSON] = [:]

    public init() {}
    public init(dictionaryLiteral elements: (String, JSON)...) {
        for (k, v) in elements { self[k] = v }
    }

    public var count: Int { keys.count }
    public var isEmpty: Bool { keys.isEmpty }
    public var values: [JSON] { keys.map { storage[$0]! } }
    /// The members as a Swift dictionary (order is lost).
    public var dictionary: [String: JSON] { storage }

    public func contains(_ key: String) -> Bool { storage[key] != nil }

    /// Setting nil removes the key.
    public subscript(key: String) -> JSON? {
        get { storage[key] }
        set {
            if let v = newValue {
                if storage.updateValue(v, forKey: key) == nil { keys.append(key) }
            } else if storage.removeValue(forKey: key) != nil {
                keys.removeAll { $0 == key }
            }
        }
    }

    @discardableResult
    public mutating func removeValue(forKey key: String) -> JSON? {
        let v = storage[key]
        self[key] = nil
        return v
    }

    public func makeIterator() -> AnyIterator<(key: String, value: JSON)> {
        var i = 0
        let ks = keys, st = storage
        return AnyIterator {
            guard i < ks.count else { return nil }
            defer { i += 1 }
            return (ks[i], st[ks[i]]!)
        }
    }

    // Equal when they hold the same members, in any order (as Python dicts compare).
    public static func == (a: JSONObject, b: JSONObject) -> Bool { a.storage == b.storage }
    public func hash(into hasher: inout Hasher) { hasher.combine(storage) }
}

// ---- writer ---------------------------------------------------------------------------------------

enum JSONWriter {
    static func write(_ v: JSON, into out: inout String, asciiOnly: Bool) {
        switch v {
        case .null: out += "null"
        case .bool(let b): out += b ? "true" : "false"
        case .number(let n): out += jsNumber(n)
        case .string(let s): writeString(s, into: &out, asciiOnly: asciiOnly)
        case .array(let a):
            out += "["
            for (i, x) in a.enumerated() {
                if i > 0 { out += "," }
                write(x, into: &out, asciiOnly: asciiOnly)
            }
            out += "]"
        case .object(let o):
            out += "{"
            var first = true
            for (k, x) in o {
                if !first { out += "," }
                first = false
                writeString(k, into: &out, asciiOnly: asciiOnly)
                out += ":"
                write(x, into: &out, asciiOnly: asciiOnly)
            }
            out += "}"
        }
    }

    static func writeString(_ s: String, into out: inout String, asciiOnly: Bool) {
        out += "\""
        for u in s.unicodeScalars {
            switch u {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\u{08}": out += "\\b"
            case "\u{0C}": out += "\\f"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            default:
                if u.value < 0x20 {
                    out += String(format: "\\u%04x", u.value)
                } else if asciiOnly && u.value > 0x7E {
                    for cu in String(u).utf16 { out += String(format: "\\u%04x", cu) }
                } else {
                    out.unicodeScalars.append(u)
                }
            }
        }
        out += "\""
    }

    /// Number::toString as ECMAScript defines it (shortest round-trip digits); NaN and
    /// infinities become null, as JSON.stringify writes them.
    static func jsNumber(_ v: Double) -> String {
        if v.isNaN || v.isInfinite { return "null" }
        if v == 0 { return "0" }
        if v < 0 { return "-" + jsNumber(-v) }
        if v < 9007199254740992, v == v.rounded() { return String(Int64(v)) }
        // the shortest digits Swift's description picks, re-laid out as JavaScript does
        let desc = "\(v)"
        var mantissa = Substring(desc), exp = 0
        if let e = desc.firstIndex(where: { $0 == "e" || $0 == "E" }) {
            mantissa = desc[..<e]
            exp = Int(desc[desc.index(after: e)...]) ?? 0
        }
        var intPart = mantissa, frac: Substring = ""
        if let dot = mantissa.firstIndex(of: ".") {
            intPart = mantissa[..<dot]
            frac = mantissa[mantissa.index(after: dot)...]
        }
        var digits = Array(intPart + frac)
        var point = intPart.count + exp
        while digits.first == "0" { digits.removeFirst(); point -= 1 }
        while digits.last == "0" { digits.removeLast() }
        if digits.isEmpty { return "0" }
        let k = digits.count, n = point
        let s = String(digits)
        if k <= n && n <= 21 { return s + String(repeating: "0", count: n - k) }
        if 0 < n && n <= 21 { return String(digits[0..<n]) + "." + String(digits[n...]) }
        if -6 < n && n <= 0 { return "0." + String(repeating: "0", count: -n) + s }
        let e = n - 1
        let es = (e < 0 ? "-" : "+") + String(abs(e))
        if k == 1 { return s + "e" + es }
        return String(digits[0]) + "." + String(digits[1...]) + "e" + es
    }
}

// ---- parser ---------------------------------------------------------------------------------------

struct JSONParseError: Error, CustomStringConvertible {
    let description: String
}

struct JSONParser {
    private let b: [UInt8]
    private var i = 0
    private var depth = 0

    init(_ bytes: [UInt8]) {
        // a leading byte order mark is skipped
        if bytes.count >= 3, bytes[0] == 0xEF, bytes[1] == 0xBB, bytes[2] == 0xBF {
            b = Array(bytes[3...])
        } else {
            b = bytes
        }
    }

    mutating func parseDocument() throws -> JSON {
        skip()
        let v = try value()
        skip()
        if i != b.count { throw JSONParseError(description: "Unexpected text after the JSON value.") }
        return v
    }

    private mutating func skip() {
        while i < b.count, b[i] == 0x20 || b[i] == 0x0A || b[i] == 0x0D || b[i] == 0x09 { i += 1 }
    }

    private mutating func value() throws -> JSON {
        guard i < b.count else { throw JSONParseError(description: "Unexpected end of JSON.") }
        switch b[i] {
        case UInt8(ascii: "{"): return try object()
        case UInt8(ascii: "["): return try array()
        case UInt8(ascii: "\""): return .string(try string())
        case UInt8(ascii: "t"): try literal("true"); return .bool(true)
        case UInt8(ascii: "f"): try literal("false"); return .bool(false)
        case UInt8(ascii: "n"): try literal("null"); return .null
        default: return .number(try number())
        }
    }

    private mutating func literal(_ word: String) throws {
        let w = Array(word.utf8)
        guard i + w.count <= b.count, Array(b[i..<(i + w.count)]) == w else {
            throw JSONParseError(description: "Invalid JSON literal.")
        }
        i += w.count
    }

    private mutating func object() throws -> JSON {
        depth += 1
        if depth > 512 { throw JSONParseError(description: "JSON nested too deeply.") }
        defer { depth -= 1 }
        i += 1
        var o = JSONObject()
        skip()
        if i < b.count, b[i] == UInt8(ascii: "}") { i += 1; return .object(o) }
        while true {
            skip()
            guard i < b.count, b[i] == UInt8(ascii: "\"") else { throw JSONParseError(description: "Expected a key.") }
            let k = try string()
            skip()
            guard i < b.count, b[i] == UInt8(ascii: ":") else { throw JSONParseError(description: "Expected ':'.") }
            i += 1
            skip()
            o[k] = try value()
            skip()
            guard i < b.count else { throw JSONParseError(description: "Unexpected end of JSON.") }
            if b[i] == UInt8(ascii: ",") { i += 1; continue }
            if b[i] == UInt8(ascii: "}") { i += 1; return .object(o) }
            throw JSONParseError(description: "Expected ',' or '}'.")
        }
    }

    private mutating func array() throws -> JSON {
        depth += 1
        if depth > 512 { throw JSONParseError(description: "JSON nested too deeply.") }
        defer { depth -= 1 }
        i += 1
        var a: [JSON] = []
        skip()
        if i < b.count, b[i] == UInt8(ascii: "]") { i += 1; return .array(a) }
        while true {
            skip()
            a.append(try value())
            skip()
            guard i < b.count else { throw JSONParseError(description: "Unexpected end of JSON.") }
            if b[i] == UInt8(ascii: ",") { i += 1; continue }
            if b[i] == UInt8(ascii: "]") { i += 1; return .array(a) }
            throw JSONParseError(description: "Expected ',' or ']'.")
        }
    }

    private mutating func hex4() throws -> UInt16 {
        guard i + 4 <= b.count, let v = UInt16(String(decoding: b[i..<(i + 4)], as: UTF8.self), radix: 16) else {
            throw JSONParseError(description: "Invalid \\u escape.")
        }
        i += 4
        return v
    }

    private mutating func string() throws -> String {
        i += 1
        var bytes: [UInt8] = []
        var units: [UInt16] = []  // pending \u escapes, joined so surrogate pairs combine
        func flushUnits() {
            if !units.isEmpty {
                // a lone surrogate becomes U+FFFD, as a JavaScript string written to UTF-8 would
                bytes.append(contentsOf: Array(String(decoding: units, as: UTF16.self).utf8))
                units.removeAll()
            }
        }
        while true {
            guard i < b.count else { throw JSONParseError(description: "Unterminated string.") }
            let c = b[i]
            if c == UInt8(ascii: "\"") { i += 1; break }
            if c == UInt8(ascii: "\\") {
                i += 1
                guard i < b.count else { throw JSONParseError(description: "Unterminated string.") }
                let e = b[i]
                i += 1
                if e == UInt8(ascii: "u") { units.append(try hex4()); continue }
                flushUnits()
                switch e {
                case UInt8(ascii: "\""): bytes.append(0x22)
                case UInt8(ascii: "\\"): bytes.append(0x5C)
                case UInt8(ascii: "/"): bytes.append(0x2F)
                case UInt8(ascii: "b"): bytes.append(0x08)
                case UInt8(ascii: "f"): bytes.append(0x0C)
                case UInt8(ascii: "n"): bytes.append(0x0A)
                case UInt8(ascii: "r"): bytes.append(0x0D)
                case UInt8(ascii: "t"): bytes.append(0x09)
                default: throw JSONParseError(description: "Invalid escape.")
                }
                continue
            }
            flushUnits()
            bytes.append(c)
            i += 1
        }
        flushUnits()
        return String(decoding: bytes, as: UTF8.self)
    }

    private mutating func number() throws -> Double {
        let start = i
        if i < b.count, b[i] == UInt8(ascii: "-") { i += 1 }
        while i < b.count, (b[i] >= 0x30 && b[i] <= 0x39) || b[i] == UInt8(ascii: ".") || b[i] == UInt8(ascii: "e")
                || b[i] == UInt8(ascii: "E") || b[i] == UInt8(ascii: "+") || b[i] == UInt8(ascii: "-") {
            i += 1
        }
        let text = String(decoding: b[start..<i], as: UTF8.self)
        guard !text.isEmpty, let d = Double(text), d.isFinite || text.lowercased().contains("e") else {
            throw JSONParseError(description: "Invalid JSON value.")
        }
        return d
    }
}

// ---- helpers the SDK uses (Python-style checks of loosely typed values) --------------------------

extension JSON {
    /// Python truthiness: null, false, 0, "" and empty arrays and objects are false.
    var truthy: Bool {
        switch self {
        case .null: return false
        case .bool(let b): return b
        case .number(let n): return n != 0 && !n.isNaN
        case .string(let s): return !s.isEmpty
        case .array(let a): return !a.isEmpty
        case .object(let o): return !o.isEmpty
        }
    }

    var isNumber: Bool { if case .number = self { return true }; return false }
    var isString: Bool { if case .string = self { return true }; return false }
    var isBool: Bool { if case .bool = self { return true }; return false }
    var isArray: Bool { if case .array = self { return true }; return false }
    var isObject: Bool { if case .object = self { return true }; return false }

    /// What Python's str() writes for the value (for building strings out of loose values).
    var pyString: String {
        switch self {
        case .string(let s): return s
        case .null: return "None"
        case .bool(let b): return b ? "True" : "False"
        case .number(let n): return n == n.rounded() && abs(n) < 1e17 ? String(Int64(n)) : JSONWriter.jsNumber(n)
        default: return jsonString
        }
    }

    /// Compact JSON with every non-ASCII character escaped (Python's json.dumps default).
    var asciiJSONString: String {
        var out = ""
        JSONWriter.write(self, into: &out, asciiOnly: true)
        return out
    }
}

extension Optional where Wrapped == JSON {
    var truthy: Bool { self?.truthy ?? false }
    var string: String? { self?.string }
    var object: JSONObject? { self?.object }
    var array: [JSON]? { self?.array }
    var number: Double? { self?.number }
    var bool: Bool? { self?.bool }
}

/// JSON text of a value, as JavaScript writes it.
func jsJSON(_ v: JSON) -> String { v.jsonString }
