import Foundation

/// Every error skapi-swift throws carries a code and a message, the same as skapi-js and skapi-py.
///
/// `code` is a short name such as `INVALID_PARAMETER`, `INVALID_REQUEST`, `NOT_EXISTS`,
/// `INCORRECT_USERNAME_OR_PASSWORD` or `MFA_REQUIRED`. `message` says what went wrong in plain
/// words. `cause` is the underlying error, when there is one.
public struct SkapiError: Error, CustomStringConvertible, LocalizedError, @unchecked Sendable {
    public let code: String
    public let message: String
    public let cause: Any?

    public init(_ message: String, code: String = "ERROR", cause: Any? = nil) {
        self.message = message
        self.code = code
        self.cause = cause
    }

    public var description: String { "\(code): \(message)" }
    public var errorDescription: String? { description }
}

/// The SDK version. 2.5.0 has the record changes of skapi-js 2.6.0 and skapi-py 2.5.0.
public let skapiVersion = "2.5.0"

func paramError(_ message: String, _ code: String = "INVALID_PARAMETER") -> SkapiError {
    SkapiError(message, code: code)
}

/// A loose value as it appears in an error message.
func jd(_ v: JSON?) -> String { (v ?? .null).jsonString }
