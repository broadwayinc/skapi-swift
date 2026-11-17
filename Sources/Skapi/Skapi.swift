import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// How many records a call returns, and which page.
public struct FetchOptions: Sendable {
    /// Records per page, up to 1000 (the server's default is 50).
    public var limit: Int?
    /// true reads the next page of the same query; false (default) starts from the first page.
    public var fetchMore: Bool
    /// Sort order: true oldest (or smallest) first.
    public var ascending: Bool?
    /// The page to start from: a startKey an earlier answer returned, "start" or "end".
    public var startKey: JSON?

    public init(limit: Int? = nil, fetchMore: Bool = false, ascending: Bool? = nil, startKey: JSON? = nil) {
        self.limit = limit
        self.fetchMore = fetchMore
        self.ascending = ascending
        self.startKey = startKey
    }

    var object: JSONObject {
        var o = JSONObject()
        if let l = limit { o["limit"] = .number(Double(l)) }
        if fetchMore { o["fetchMore"] = true }
        if let a = ascending { o["ascending"] = .bool(a) }
        if let s = startKey { o["startKey"] = s }
        return o
    }
}

/// One Skapi project, its connection, and the signed-in user's session.
///
/// ```swift
/// let skapi = try Skapi(projectId: "<Project ID>")   // from your project's Settings page on skapi.com
/// let profile = try await skapi.login(email: "user@example.com", password: "password")
/// ```
///
/// Skapi is an actor: every call is `await`ed, and calls from many tasks at once are safe.
public actor Skapi {
    static let tokenRefreshSkew: Double = 60 * 60  // refresh the ID token when it has less than an hour left

    /// The compact Project ID.
    public nonisolated let projectId: String
    /// The project's service id.
    public nonisolated let service: String
    /// The project owner's id.
    public nonisolated let owner: String
    /// The SDK version.
    public nonisolated let version: String = skapiVersion

    /// The project's connection info as the server answered it, once connected.
    public private(set) var connection: JSONObject?

    let requester: Requester
    let storage: SkapiStorage
    let deviceKeyStorage: SkapiStorage?
    let urlSession: URLSession
    let observeAppLifecycle: Bool
    var pool: UserPool?
    var sess: SkapiSession?
    var cognitoUsername: String?
    var userObj: JSONObject?
    var restoreTask: Task<Bool, Never>?
    var restoreDone = false
    var connectionTask: Task<JSONObject, Error>?
    var refreshTask: Task<Void, Error>?
    /// Counts sign-outs: a token refresh that started before a sign-out compares it before adopting
    /// its tokens, so a refresh still running when the user logged out cannot sign them back in.
    var signOuts = 0
    var restoreRefreshedToken: String?
    var enc: EncState?

    // per-instance state, as in skapi-js
    var privateAccessKey: [String: String] = [:]
    var myUniqueIds: [String: [String: String]] = [:]
    var handedOutFileUrls: [String: String] = [:]  // getFile url given out -> the stored file url
    var pendingMFA: (username: String, session: String?, password: String)?
    var requestSignupConfirmation: String?
    var disabledAccount: String?
    var anonymousTask: Task<Void, Never>?
    var lastAnonymousBeat: Date?
    var bulkPermitsUnavailable = false
    var rt: RealtimeConnection?
    var lifecycle: LifecycleObserver?

    /// projectId: the Project ID from your project's Settings page on skapi.com.
    /// storage: where the signed-in session is kept between launches. Default: the Keychain on
    ///   iOS and macOS (one Keychain service per project), memory elsewhere. Pass `MemoryStorage()`
    ///   to forget the session when the object goes away, or your own `SkapiStorage`.
    /// timeout: seconds to wait for each request.
    /// encryption: seals the data of private records on this device before upload (see
    ///   `EncryptionOptions`).
    /// observeAppLifecycle: when the app comes back to the foreground or the network returns,
    ///   check the realtime connection and an anonymous account at once (as skapi-js does when a
    ///   browser tab becomes visible again).
    public init(projectId: String, storage: SkapiStorage? = nil, timeout: TimeInterval = 120, targetCDN: String? = nil,
                encryption: EncryptionOptions? = nil, urlSession: URLSession = .shared, observeAppLifecycle: Bool = true) throws {
        let trimmed = projectId.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { throw paramError("Project ID is required.") }
        if !ProjectID.isProjectId(trimmed) { throw paramError("Project ID is invalid.") }
        let (service, owner) = try ProjectID.decode(trimmed)
        self.service = service
        self.owner = owner
        self.projectId = ProjectID.format(service: service, owner: owner) ?? ""
        self.urlSession = urlSession
        self.requester = Requester(service: service, owner: owner, version: skapiVersion, targetCDN: targetCDN, timeout: timeout, session: urlSession)
        self.storage = storage ?? defaultStorage(service: service)
        self.observeAppLifecycle = observeAppLifecycle
        if let e = encryption {
            try e.validate()
            self.enc = EncState(e)
            self.deviceKeyStorage = e.persistDevice ? (e.deviceKeyStorage ?? defaultDeviceKeyStorage(service: service)) : nil
        } else {
            self.deviceKeyStorage = nil
        }
    }

    // ---- connection -----------------------------------------------------------------------------

    @discardableResult
    func ensureConnection(refresh: Bool = false) async throws -> JSONObject {
        if !refresh, let c = connection { return c }
        if !refresh, let t = connectionTask { return try await t.value }
        let requester = self.requester, service = self.service, owner = self.owner
        let t = Task { () throws -> JSONObject in
            let v = try await requester.request("service", ["service": .string(service), "owner": .string(owner), "refresh": .bool(refresh)], method: "GET")
            return v.object ?? JSONObject()
        }
        connectionTask = t
        do {
            let c = try await t.value
            connection = c
            connectionTask = nil
            startLifecycleIfNeeded()
            return c
        } catch {
            connectionTask = nil
            throw error
        }
    }

    /// The project's name and settings, and the caller's IP and location as the server sees them.
    public func getConnectionInfo(refresh: Bool = false) async throws -> JSON {
        let conn = try await ensureConnection(refresh: refresh)
        var info: JSONObject = [
            "project_id": .string(projectId),
            "user_ip": conn["ip"] ?? .null,
            "user_agent": conn["user_agent"] ?? .null,
            "user_location": conn["locale"] ?? .null,
            "service_name": conn["service_name"] ?? .null,
            "version": .string(version),
            "ai_agent": conn["ai_agent"] ?? .null,
            "conf": conn["opt"] ?? .null,
        ]
        // Only with encryption on and a signed-in user: the encryption recovery code on the first call
        // after it was created, then only a message.
        if let recovery = await encryptionRecoveryInfo() { info["encryption_recovery"] = recovery }
        return .object(info)
    }

    // ---- session --------------------------------------------------------------------------------

    func userPool() async throws -> UserPool {
        if let p = pool { return p }
        let (admin, _) = try await requester.endpoints()
        if let p = pool { return p }
        let p = try UserPool(userPoolId: admin["userpool_id"]?.string ?? "", clientId: admin["userpool_client"]?.string ?? "",
                             storage: storage, session: urlSession)
        pool = p
        return p
    }

    /// Once: sign back in from storage (refreshing the tokens when they expired).
    func restore() async {
        if restoreDone { return }
        if let t = restoreTask { _ = await t.value; return }
        let t = Task { await self.performRestore() }
        restoreTask = t
        if await t.value {
            restoreDone = true
            startDeviceUnlockIfNeeded()
        } else {
            restoreTask = nil  // the endpoints could not be read: try again on the next call
        }
    }

    /// false when the project's endpoints could not be read (offline at launch).
    private func performRestore() async -> Bool {
        guard let pool = try? await userPool() else { return false }
        guard let username = pool.lastAuthUser(), !username.isEmpty, var session = pool.cachedSession(username) else { return true }
        do {
            if !session.isValid {
                if session.refreshToken.isEmpty { return true }
                do {
                    session = try await pool.refresh(username: username, refreshToken: session.refreshToken)
                    // getProfile(refreshToken: true) right after this has nothing left to ask for
                    restoreRefreshedToken = session.idToken.jwtToken
                } catch let e as CognitoError where e.code == "NetworkError" {
                    // The server never answered: that says nothing about the session, which is kept with its
                    // stored tokens. The next signed-in call refreshes again (NETWORK_ERROR while offline).
                }
            }
            try adoptSession(username, session)
            if userObj?["anonymous"]?.bool == true {
                // a temporary account restored from storage: check it still exists, and keep it alive
                startAnonymousKeepAlive(beatNow: true)
            }
        } catch let e as CognitoError {
            if e.code != "NetworkError" { clearSession() }
        } catch {}
        return true
    }

    @discardableResult
    func adoptSession(_ username: String, _ session: SkapiSession) throws -> JSONObject {
        let claims = session.idToken.payload
        if claims["custom:service"]?.string != service {
            clearSession()
            throw SkapiError("Invalid session.", code: "INVALID_REQUEST")
        }
        if let previous = cognitoUsername, previous != username {
            // a new sign-in as someone else: nothing the previous user was handed carries over
            privateAccessKey.removeAll()
            myUniqueIds.removeAll()
            encClear(deleteDevice: true)  // the previous user's remembered key leaves this device too
            if let p = pool {
                stopAnonymousKeepAlive()
                for key in ["idToken", "accessToken", "refreshToken", "clockDrift", "userData"] {
                    p.storage.removeItem("\(p.keyPrefix).\(previous).\(key)")
                }
            }
        }
        sess = session
        cognitoUsername = username
        let u = parseUserAttributes(claims)
        userObj = u
        return u
    }

    func clearSession() {
        if let r = rt {
            rt = nil
            r.close()  // a signed-in connection does not outlive the session
        }
        stopAnonymousKeepAlive()
        encClear(deleteDevice: true)
        pendingMFA = nil
        if let u = cognitoUsername, let p = pool { p.clearCachedTokens(u) }
        sess = nil
        cognitoUsername = nil
        userObj = nil
        signOuts += 1  // a refresh still running from before this point is not adopted
        restoreRefreshedToken = nil
        privateAccessKey.removeAll()
        myUniqueIds.removeAll()
        requester.clearStartKeyHistory()
    }

    func signedIn() async -> Bool {
        await restore()
        return userObj != nil && sess != nil
    }

    /// Forced token refresh. A network failure keeps the session; any other refusal ends it.
    func refreshSession() async throws {
        if let t = refreshTask { _ = try? await t.value }
        let t = Task { try await self.performRefresh() }
        refreshTask = t
        defer { if refreshTask == t { refreshTask = nil } }
        try await t.value
    }

    private func performRefresh() async throws {
        guard let s = sess, let username = cognitoUsername else { throw SkapiError("User login is required.", code: "INVALID_REQUEST") }
        let epoch = signOuts
        let pool = try await userPool()
        let fresh: SkapiSession
        do {
            fresh = try await pool.refresh(username: username, refreshToken: s.refreshToken)
        } catch let e as CognitoError {
            if signOuts != epoch { try signedOutMeanwhile(pool, username) }
            if e.code == "NetworkError" { throw SkapiError("Network error", code: "NETWORK_ERROR", cause: e) }
            clearSession()
            throw SkapiError("User login is required.", code: "INVALID_REQUEST", cause: e)
        }
        if signOuts != epoch { try signedOutMeanwhile(pool, username) }
        try adoptSession(username, fresh)
    }

    /// logout() ran while a token refresh waited on the server: the refresh is not adopted, and the
    /// tokens it wrote back to storage are removed again (a sign-in made after the logout keeps its own).
    private func signedOutMeanwhile(_ pool: UserPool, _ username: String) throws {
        pool.clearCachedTokens(username)
        if let s = sess, let u = cognitoUsername { pool.cacheTokens(u, s) }
        throw SkapiError("User login is required.", code: "INVALID_REQUEST")
    }

    func freshIdToken() async throws -> String {
        await restore()
        guard let s = sess else {
            clearSession()
            throw SkapiError("User login is required.", code: "INVALID_REQUEST")
        }
        let now = Date().timeIntervalSince1970
        if s.idToken.expiration < now + Skapi.tokenRefreshSkew {
            if let t = refreshTask { try await t.value }  // another call is refreshing: share it
            guard let s2 = sess else { throw SkapiError("User login is required.", code: "INVALID_REQUEST") }
            if s2.idToken.expiration < Date().timeIntervalSince1970 + Skapi.tokenRefreshSkew { try await refreshSession() }
        }
        guard let s3 = sess else { throw SkapiError("User login is required.", code: "INVALID_REQUEST") }
        return s3.idToken.jwtToken
    }

    func accessToken() async throws -> String {
        _ = try await freshIdToken()
        guard let s = sess else { throw SkapiError("User login is required.", code: "INVALID_REQUEST") }
        return s.accessToken.jwtToken
    }

    func call(_ path: String, _ data: JSON? = nil, auth: Bool = false, method: String = "POST",
              fetchOptions: JSONObject? = nil, ignoreService: Bool = false) async throws -> JSON {
        try await ensureConnection()
        let token = auth ? try await freshIdToken() : nil
        return try await requester.request(path, data, auth: auth, method: method, token: token, fetchOptions: fetchOptions,
                                           ignoreService: ignoreService)
    }

    /// The signed-in user's profile, or nil.
    public var user: JSON? {
        get async {
            await restore()
            return userObj.map { .object($0) }
        }
    }

    /// The signed-in session's tokens (idToken, accessToken, refreshToken), or nil.
    public var session: SkapiSession? {
        get async {
            await restore()
            return sess
        }
    }

    var me: String { userObj?["user_id"]?.string ?? "" }
    var isAnonymous: Bool { userObj?["anonymous"]?.bool == true }
}
