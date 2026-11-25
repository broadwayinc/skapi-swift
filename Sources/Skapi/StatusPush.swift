import Foundation

/// A request status event (skapi-js 2.5.0 onRequestStatus).
///
/// type "status": one of your forwarded requests dispatched with `notify` changed status. `id` is the
/// request id the dispatch reply handed back ("stamp:entropy"), `status` the new status (pending,
/// running, resolved, failed, cancelled), `previous` the one before (absent when it was just created),
/// `updated` when the row changed and `executed` when the server began running it, both in milliseconds.
///
/// type "connected" / "disconnected": the realtime connection the events ride on came up or went away.
/// Events sent while it was away are lost, so re-read what you show on "connected".
///
/// An event is a hint, never the outcome: read the request (its poll, forwardRequestRead or
/// forwardRequestStatus) for that.
public struct RequestStatusEvent: Sendable {
    public let type: String
    public let id: String?
    public let queue: String?
    public let status: String?
    public let previous: String?
    public let updated: Double?
    public let executed: Double?

    init(type: String, id: String? = nil, queue: String? = nil, status: String? = nil, previous: String? = nil,
         updated: Double? = nil, executed: Double? = nil) {
        self.type = type
        self.id = id
        self.queue = queue
        self.status = status
        self.previous = previous
        self.updated = updated
        self.executed = executed
    }

    /// The event as an object with the skapi-js keys.
    public var json: JSON {
        var o: JSONObject = ["type": .string(type)]
        if let v = id { o["id"] = .string(v) }
        if let v = queue { o["queue"] = .string(v) }
        if let v = status { o["status"] = .string(v) }
        if let v = previous { o["previous"] = .string(v) }
        if let v = updated { o["updated"] = .number(v) }
        if let v = executed { o["executed"] = .number(v) }
        return .object(o)
    }
}

/// "stamp:entropy" from any form of a request id (a full id ends with it).
func shortRequestId(_ id: String) -> String {
    let parts = id.components(separatedBy: ":")
    return parts.count >= 2 ? parts[parts.count - 2] + ":" + parts[parts.count - 1] : id
}

/// Request status push, ported from skapi-js src/methods/request_status.ts.
///
/// A request dispatched with `notify: true` is stamped by the server with the caller's user, and every
/// status change of it arrives on that user's realtime connections as one private frame
/// `{"#private": {"v": 1, "ev": [{id, q, s, p, t, att}, ...]}, "#code": "CSR_STATUS"}`. The frame is
/// a hint: a poll that a frame names reads the row at once, and the row settles it, so a lost, late,
/// duplicated or forged frame costs at most one read or one slow interval.
///
/// The frames ride on the Skapi object's one realtime connection and never reach the app's own realtime
/// callback. A connection is opened only when there is none and a user is signed in, and only a
/// connection this module opened is ever closed by it, and only while no group is joined on it.
final class StatusPush: @unchecked Sendable {
    /// While frames are arriving, a poll of a `notify` request reads the row only this often on its
    /// own (a heartbeat), and otherwise when a frame names it.
    static let idlePollMs: Double = 60 * 1000
    /// How long a connection this module opened stays open after the last holder let go.
    static let lingerSeconds: Double = 10 * 60
    /// How soon to look again for a connection after the one in use went away.
    static let reattachSeconds: Double = 3

    private let lock = NSRecursiveLock()
    private weak var skapi: Skapi?
    private var holders = 0
    /// The server accepted `notify` at least once: frames can exist for this client.
    private var acked = false
    /// The open connection the listener is on.
    private weak var current: RealtimeConnection?
    /// The connection this module opened, and so may close.
    private weak var opened: RealtimeConnection?
    /// A frame arrived on the current connection since it opened.
    private var frameSeen = false
    private var attaching = false
    private var retryTask: Task<Void, Never>?
    private var lingerTask: Task<Void, Never>?
    private var listeners: [Int: @Sendable (RequestStatusEvent) -> Void] = [:]
    private var wakers: [String: [Int: @Sendable () -> Void]] = [:]
    private var nextId = 0

    /// The server acknowledged `notify` on a dispatch.
    func noteAck() { lock.locked { acked = true } }

    /// True while status frames are known to be arriving: the server accepted `notify`, the listener
    /// is on an open connection, and a frame came in on it. Only then may a poll slow down.
    var warm: Bool {
        lock.locked { acked && frameSeen && (current?.isOpen ?? false) }
    }

    /// Run `wake` whenever a frame names this request. Returns the unregister.
    func addWaker(_ id: String, _ wake: @escaping @Sendable () -> Void) -> @Sendable () -> Void {
        let key = shortRequestId(id)
        let token: Int = lock.locked {
            nextId += 1
            wakers[key, default: [:]][nextId] = wake
            return nextId
        }
        return { [weak self] in
            guard let self = self else { return }
            self.lock.locked {
                self.wakers[key]?[token] = nil
                if self.wakers[key]?.isEmpty == true { self.wakers[key] = nil }
            }
        }
    }

    /// Keep the listener attached (opening a connection when none exists and a user is signed in).
    /// Returns the matching release; a connection this module opened closes `lingerSeconds` after the
    /// last holder let go.
    func hold(_ s: Skapi) -> @Sendable () -> Void {
        lock.locked {
            skapi = s
            holders += 1
            lingerTask?.cancel()
            lingerTask = nil
        }
        attach()
        let once = ReleaseOnce()
        return { [weak self] in
            guard once.claim(), let self = self else { return }
            self.lock.locked {
                self.holders = max(0, self.holders - 1)
                if self.holders > 0 { return }
                self.scheduleLinger()
            }
        }
    }

    /// Closes the connection this module opened `lingerSeconds` from now, unless a holder comes back.
    /// Called with the lock held.
    private func scheduleLinger() {
        lingerTask?.cancel()
        lingerTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(StatusPush.lingerSeconds * 1_000_000_000))
            if Task.isCancelled { return }
            self?.releaseIfIdle()
        }
    }

    /// Adds a listener (onRequestStatus). Returns the remover.
    func listen(_ s: Skapi, _ callback: @escaping @Sendable (RequestStatusEvent) -> Void) -> @Sendable () -> Void {
        let (token, liveNow): (Int, Bool) = lock.locked {
            nextId += 1
            listeners[nextId] = callback
            return (nextId, current?.isOpen ?? false)
        }
        let unhold = hold(s)
        if liveNow {
            // Already listening: this subscriber starts from a live connection too.
            Task { [weak self] in
                guard let self = self, self.lock.locked({ self.listeners[token] != nil }) else { return }
                callback(RequestStatusEvent(type: "connected"))
            }
        }
        return { [weak self] in
            guard let self = self else { return }
            let removed: Bool = self.lock.locked { self.listeners.removeValue(forKey: token) != nil }
            if removed { unhold() }
        }
    }

    private func emit(_ e: RequestStatusEvent) {
        let cbs = lock.locked { Array(listeners.values) }
        for cb in cbs { cb(e) }  // each listener runs; one cannot cost the others their event
    }

    // ---- connection events (from RealtimeConnection) ------------------------------------------------

    /// A realtime connection opened (first open or a reconnect).
    func connectionOpened(_ r: RealtimeConnection) {
        lock.locked {
            current = r
            frameSeen = false
        }
        emit(RequestStatusEvent(type: "connected"))
    }

    /// A realtime connection went away (dropped or closed).
    func connectionLost(_ r: RealtimeConnection) {
        let was: Bool = lock.locked {
            guard current === r else { return false }
            current = nil
            frameSeen = false
            return true
        }
        if was { emit(RequestStatusEvent(type: "disconnected")) }
        scheduleAttach()
    }

    /// The app took over the connection (connectRealtime on one this module opened): never close it.
    func appAdopted(_ r: RealtimeConnection) {
        lock.locked { if opened === r { opened = nil } }
    }

    /// True for a frame that is a server status push (and so not the app's business).
    static func isStatusFrame(_ data: JSONObject) -> Bool {
        data["#code"]?.string == "CSR_STATUS" && (data["#private"]?.truthy ?? false) && !(data["#user_id"]?.truthy ?? false)
    }

    func onFrame(_ data: JSONObject, from r: RealtimeConnection) {
        var body = data["#private"] ?? .null
        if let s = body.string {
            guard let parsed = try? JSON.parse(s) else { return }
            body = parsed
        }
        lock.locked { if current === r { frameSeen = true } }
        for e in body["ev"]?.array ?? [] {
            guard let id = e["id"]?.string, let s = e["s"]?.string else { continue }
            let event = RequestStatusEvent(type: "status", id: id, queue: e["q"]?.string, status: s, previous: e["p"]?.string,
                                           updated: e["t"]?.number, executed: e["att"]?.number)
            let wake = lock.locked { Array((wakers[id] ?? [:]).values) }
            for w in wake { w() }
            emit(event)
        }
    }

    // ---- attaching ------------------------------------------------------------------------------------

    private func scheduleAttach() {
        lock.locked {
            if holders == 0 || retryTask != nil { return }
            retryTask = Task { [weak self] in
                try? await Task.sleep(nanoseconds: UInt64(StatusPush.reattachSeconds * 1_000_000_000))
                guard let self = self else { return }
                self.lock.locked { self.retryTask = nil }
                self.attach()
            }
        }
    }

    private func attach() {
        let s: Skapi? = lock.locked {
            guard holders > 0, !attaching, let s = skapi else { return nil }
            if current?.isOpen ?? false { return nil }
            attaching = true
            return s
        }
        guard let skapi = s else { return }
        Task {
            let outcome = await skapi.statusPushAttach()
            self.lock.locked { self.attaching = false }
            switch outcome {
            case .attached(let r, let openedHere):
                self.lock.locked {
                    // The app may have taken it (connectRealtime) while it opened: then it is the app's.
                    if openedHere && !r.appOwned {
                        self.opened = r
                        // every holder let go while it opened: it still closes after the linger
                        if self.holders == 0 { self.scheduleLinger() }
                    }
                    if self.current !== r {
                        self.current = r
                        self.frameSeen = false
                    }
                }
            case .retry:
                self.scheduleAttach()
            case .noSession:
                break
            }
        }
    }

    private func releaseIfIdle() {
        let (s, r): (Skapi?, RealtimeConnection?) = lock.locked {
            guard holders == 0 else { return (nil, nil) }
            retryTask?.cancel()
            retryTask = nil
            let r = opened
            opened = nil
            return (skapi, r)
        }
        guard let skapi = s, let conn = r else { return }
        Task { await skapi.statusPushRelease(conn) }
    }
}

private final class ReleaseOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false
    func claim() -> Bool { lock.locked { if done { return false }; done = true; return true } }
}

enum StatusPushAttach {
    case attached(RealtimeConnection, openedHere: Bool)
    case retry
    case noSession
}

extension Skapi {
    /// Finds the realtime connection for status push, opening one when none exists and a user is
    /// signed in.
    func statusPushAttach() async -> StatusPushAttach {
        if let r = rt, !r.isClosing {
            return r.isOpen ? .attached(r, openedHere: false) : .retry  // a reconnect is under way
        }
        guard (try? await ensureConnection()) != nil else { return .retry }
        guard await signedIn() else { return .noSession }
        if let r = rt, !r.isClosing { return r.isOpen ? .attached(r, openedHere: false) : .retry }
        let r = RealtimeConnection(skapi: self, callback: { _ in })
        rt = r
        let opening = Task { try await r.open() }
        r.opening = opening  // an app's connectRealtime meanwhile waits for this open
        do {
            try await opening.value
            r.opening = nil
            return .attached(r, openedHere: true)
        } catch {
            r.opening = nil
            if rt === r { rt = nil }
            return .retry
        }
    }

    /// Closes a connection status push opened, when it is still the object's connection and no group
    /// is joined on it (the app would be using it).
    func statusPushRelease(_ r: RealtimeConnection) {
        if rt === r, r.room == nil, !r.appOwned { closeRealtime() }
    }

    /// Listens to status changes of this user's forwarded requests dispatched with `notify: true`,
    /// including ones this client holds no poll for (a pass the server queued as the continuation of
    /// one, or a request sent from another device of the same user). Each change arrives as a
    /// `RequestStatusEvent` of type "status".
    ///
    /// The realtime connection is kept open while a listener is registered (one is opened when the app
    /// has none and a user is signed in; the app's own realtime callback never sees these frames). The
    /// callback also gets type "connected" whenever the listener lands on an open connection, first time
    /// and after every reconnect, and "disconnected" when it loses it. Frames are not kept for a
    /// connection that is down, so re-read what you show on "connected".
    ///
    /// A status event is a hint, not the outcome: read the request for that.
    /// Returns a function that removes the listener.
    @discardableResult
    public nonisolated func onRequestStatus(_ callback: @escaping @Sendable (RequestStatusEvent) -> Void) -> @Sendable () -> Void {
        statusPush.listen(self, callback)
    }

    /// True while request status frames are arriving on this client (see onRequestStatus). Polls of
    /// `notify` requests run slowly only while this is true.
    public nonisolated func isRequestStatusLive() -> Bool {
        statusPush.warm
    }
}
