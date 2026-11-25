import XCTest
@testable import Skapi

/// Offline checks for the 2.5.0 record changes: source["can_modify_referencing_records"],
/// record["updated_by"] (from prv_acs.upb) and the redacted "ip" field. No network calls: the
/// records carry no files and no offloaded data, and decryption is skipped.
final class RecordDecodingTests: XCTestCase {
    // A made-up long-form Project ID (7 parts); nothing is ever sent to it.
    static let projectId = "abcd-0efgh-12345678-1234-1234-1234-123456789012"

    func makeSkapi() throws -> Skapi {
        try Skapi(projectId: Self.projectId, storage: MemoryStorage(), observeAppLifecycle: false)
    }

    func record(_ extra: JSONObject = [:]) -> JSON {
        var r: JSONObject = ["rec": "1AbCdEfGh12345abcd", "usr": "user-b", "tbl": "comments/service-id/00",
                             "ip": "203.0.113.5#", "prv_acs": .object(JSONObject())]
        for (k, v) in extra { r[k] = v }
        return .object(r)
    }

    func decode(_ skapi: Skapi, _ r: JSON) async throws -> JSON {
        try await skapi.normalizeRecord(r, skipDataFetch: true, skipBinResolve: true, skipDecrypt: true)
    }

    func testVersion() {
        XCTAssertEqual(skapiVersion, "2.7.0")
    }

    func testSourceDefaultsIncludeCanModifyReferencingRecords() async throws {
        let r = try await decode(try makeSkapi(), record())
        XCTAssertEqual(r["source"]?["can_modify_referencing_records"]?.bool, false)
        XCTAssertNil(r["updated_by"])
    }

    func testCanModifyReferencingRecordsReturnedInSource() async throws {
        let r = try await decode(try makeSkapi(), record(["prv_acs": ["can_modify_referencing_records": true]]))
        XCTAssertEqual(r["source"]?["can_modify_referencing_records"]?.bool, true)
    }

    func testUpbBecomesUpdatedByAndNeverASourceSetting() async throws {
        let r = try await decode(try makeSkapi(), record(["prv_acs": ["upb": "user-a", "can_remove_referencing_records": true]]))
        XCTAssertEqual(r["updated_by"]?.string, "user-a")
        XCTAssertNil(r["source"]?["upb"])
        XCTAssertEqual(r["source"]?["can_remove_referencing_records"]?.bool, true)
        XCTAssertEqual(r["user_id"]?.string, "user-b")
    }

    func testEmptyUpbIsIgnored() async throws {
        let r = try await decode(try makeSkapi(), record(["prv_acs": ["upb": ""]]))
        XCTAssertNil(r["updated_by"])
        XCTAssertNil(r["source"]?["upb"])
    }

    func testFullIpForTheUploader() async throws {
        let r = try await decode(try makeSkapi(), record(["ip": "203.0.113.5R#my-id"]))
        XCTAssertEqual(r["ip"]?.string, "203.0.113.5")
        XCTAssertEqual(r["readonly"]?.bool, true)
        XCTAssertEqual(r["unique_id"]?.string, "my-id")
    }

    func testRedactedIpOfASignedInUploader() async throws {
        let skapi = try makeSkapi()
        let cases: [(JSON, Bool, String?)] = [
            ("R#my#id", true, "my#id"),
            ("#my-id", false, "my-id"),
            ("R", true, nil),
            ("", false, nil),
            (.null, false, nil),
        ]
        for (ip, readonly, uid) in cases {
            let r = try await decode(skapi, record(["ip": ip]))
            XCTAssertEqual(r["ip"]?.string, "", "ip for \(ip)")
            XCTAssertEqual(r["readonly"]?.bool, readonly, "readonly for \(ip)")
            XCTAssertEqual(r["unique_id"]?.string, uid, "unique_id for \(ip)")
            XCTAssertEqual(r["user_id"]?.string, "user-b", "user_id for \(ip)")
        }
    }

    func testRedactedIpOfAnAnonymousUploaderStillReadsAsAnonymous() async throws {
        let r = try await decode(try makeSkapi(), record(["ip": "0-0-0-0R#anon-id"]))
        XCTAssertEqual(r["ip"]?.string, "0.0.0.0")
        XCTAssertEqual(r["readonly"]?.bool, true)
        XCTAssertEqual(r["unique_id"]?.string, "anon-id")
        XCTAssertEqual(r["user_id"]?.string, "anonymous:user-b")
    }
}
