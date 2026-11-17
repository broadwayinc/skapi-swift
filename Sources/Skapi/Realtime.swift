import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// A realtime message, notice or connection event, shaped as in skapi-js.
///
/// type: "message" (group message), "private" (one to one), "notice" (presence: code USER_JOINED,
/// USER_LEFT, USER_DISCONNECTED), "error", and the connection events "success", "close", "reconnect".
public struct RealtimeEvent: Sendable {
    public let type: String
    public let message: JSON
    /// The sender's user ID.
    public let sender: String?
    /// The sender's connection id ("cid:...").
    public let senderCid: String?
    /// The group the message was sent to.
    public let senderRid: String?
    public let code: String?

    init(type: String, message: JSON, sender: String? = nil, senderCid: String? = nil, senderRid: String? = nil, code: String? = nil) {
        self.type = type
        self.message = message
        self.sender = sender
        self.senderCid = senderCid
        self.senderRid = senderRid
        self.code = code
    }

    func with(message m: JSON) -> RealtimeEvent {
        RealtimeEvent(type: type, message: m, sender: sender, senderCid: senderCid, senderRid: senderRid, code: code)
    }

    /// The event as an object with the skapi-js keys (type, message, sender, sender_cid, sender_rid, code).
    public var json: JSON {
        ["type": .string(type), "message": message, "sender": JSON(sender), "sender_cid": JSON(senderCid),
         "sender_rid": JSON(senderRid), "code": JSON(code)]
    }
}

/// One WebSocket (URLSessionWebSocketTask), with its opening handshake awaited.
final class WebSocketConnection: NSObject, URLSessionWebSocketDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var session: URLSession!
    private var task: URLSessionWebSocketTask!
    private var openWaiter: CheckedContinuation<Void, Error>?
    private var opened = false
    private var finished: Error?
    private(set) var closed = false

    init(url: URL) {
        super.init()
        session = URLSession(configuration: .default, delegate: self, delegateQueue: nil)
        task = session.webSocketTask(with: url)
        task.maximumMessageSize = 4 * 1024 * 1024
    }

    func open(timeout: TimeInterval = 30) async throws {
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
            lock.lock()
            openWaiter = c
            lock.unlock()
            task.resume()
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { [weak self] in
                self?.resolveOpen(URLError(.timedOut))
            }
        }
    }

    private func resolveOpen(_ error: Error?) {
        lock.lock()
        let w = openWaiter
        openWaiter = nil
        if error == nil { opened = true }
        lock.unlock()
        if let e = error { w?.resume(throwing: e) } else { w?.resume() }
    }

    func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask, didOpenWithProtocol protocol: String?) {
        resolveOpen(nil)
    }

    func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask, didCloseWith closeCode: URLSessionWebSocketTask.CloseCode, reason: Data?) {
        markClosed()
        resolveOpen(URLError(.networkConnectionLost))
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        markClosed()
        resolveOpen(error ?? URLError(.networkConnectionLost))
    }

    private func markClosed() {
        lock.lock(); closed = true; lock.unlock()
    }

    var isClosed: Bool { lock.lock(); defer { lock.unlock() }; return closed }

    func send(_ text: String) async throws {
        if isClosed { throw URLError(.networkConnectionLost) }
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
            task.send(.string(text)) { error in
                if let e = error { c.resume(throwing: e) } else { c.resume() }
            }
        }
    }

    func receive() async throws -> String {
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<String, Error>) in
            task.receive { [weak self] result in
                switch result {
                case .success(.string(let s)): c.resume(returning: s)
                case .success(.data(let d)): c.resume(returning: String(decoding: d, as: UTF8.self))
                case .success: c.resume(returning: "")
                case .failure(let e):
                    self?.markClosed()
                    c.resume(throwing: e)
                }
            }
        }
    }

    func close() {
        lock.lock()
        let was = closed
        closed = true
        lock.unlock()
        if !was { task.cancel(with: .normalClosure, reason: nil) }
        session.finishTasksAndInvalidate()
    }
}

/// The live state of one Skapi object's realtime connection, ported from skapi-py (_realtime.py)
/// and skapi-js (src/methods/realtime.ts) without WebRTC: one connection, one group at a time, private
/// messages, presence notices, keep-alive, planned renewal before the server's 2 hour cut, reconnects.
final class RealtimeConnection: @unchecked Sendable {
    static let pingInterval: TimeInterval = 60
    static let pongTimeout: TimeInterval = 10
    static let ponglessPingsDead = 3
    static let connectionLifetime: TimeInterval = 7200
    static let renewBefore: TimeInterval = 300
    static let renewJitter: TimeInterval = 120
    static let joinWait: TimeInterval = 3
    static let sendWindow: TimeInterval = 0.1
    static let seqWait: TimeInterval = 1.5
    static let maxFrameBytes = 32768
    static let batchChars = maxFrameBytes - 2048
    static let maxNotificationBytes = 3072

    weak var skapi: Skapi?
    private let lock = NSRecursiveLock()
    private var callback: @Sendable (RealtimeEvent) -> Void
    private(set) var ws: WebSocketConnection?
    private(set) var closing = false
    private var _room: String?
    var room: String? {
        get { lock.locked { _room } }
        set { lock.locked { _room = newValue } }
    }
    private var reconnectAttempts = 0
    private var seq = 0
    private var order: [String: (next: Int, waiting: [Int: RealtimeEvent], timer: Task<Void, Never>?)] = [:]
    private var _joinWait: (group: String, until: Date, signaled: Bool)?
    var joinWaitState: (group: String, until: Date, signaled: Bool)? {
        get { lock.locked { _joinWait } }
        set { lock.locked { _joinWait = newValue } }
    }
    private var pongSeen = false
    private var ponglessPings = 0
    private var pongDeadline: Date?
    private var pingSentAt = Date.distantPast
    private var renewAt = Date.distantFuture
    private var generation = 0
    private var lastSend: [String: Date] = [:]
    private var window: (group: String, items: [JSON], base: JSONObject, timer: Task<Void, Never>)?
    private var reconnecting = false

    init(skapi: Skapi, callback: @escaping @Sendable (RealtimeEvent) -> Void) {
        self.skapi = skapi
        self.callback = callback
    }

    func setCallback(_ cb: @escaping @Sendable (RealtimeEvent) -> Void) {
        lock.lock(); callback = cb; lock.unlock()
    }

    var isOpen: Bool {
        lock.lock(); defer { lock.unlock() }
        return ws.map { !$0.isClosed } ?? false
    }

    var isClosing: Bool { lock.lock(); defer { lock.unlock() }; return closing }

    func emit(_ e: RealtimeEvent) {
        lock.lock()
        let cb = callback
        lock.unlock()
        cb(e)
    }

    private func current(_ g: Int) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return g == generation && !closing
    }

    // ---- connection -------------------------------------------------------------------------------

    /// Opens a socket (fresh token first) and starts its reader and keep-alive tasks.
    func open(renew: Bool = false) async throws {
        guard let skapi = skapi else { throw SkapiError("No access.", code: "INVALID_REQUEST") }
        let token = try await skapi.accessToken()
        let (_, record) = try await skapi.requester.endpoints()
        guard let base = record["websocket_private"]?.string, let url = URL(string: base + "?token=" + token) else {
            throw SkapiError("WebSocket closed before it opened.", code: "INVALID_REQUEST")
        }
        let conn = WebSocketConnection(url: url)
        do { try await conn.open() } catch {
            conn.close()
            throw SkapiError("WebSocket closed before it opened.", code: "INVALID_REQUEST", cause: error)
        }
        let (old, gen, joined) = lock.locked { () -> (WebSocketConnection?, Int, String?) in
            let old = ws
            ws = conn
            generation += 1
            pongSeen = false
            ponglessPings = 0
            pongDeadline = nil
            reconnectAttempts = 0
            renewAt = Date().addingTimeInterval(RealtimeConnection.connectionLifetime - RealtimeConnection.renewBefore
                                                - Double.random(in: 0..<1) * RealtimeConnection.renewJitter)
            return (old, generation, _room)
        }
        if !renew { emit(RealtimeEvent(type: "success", message: "Connected to WebSocket server.")) }
        forgetOrder()
        if let r = joined {
            let at = await skapi.currentAccessToken() ?? ""
            try? await sendRaw(["action": "joinRoom", "rid": .string(r), "token": .string(at), "ver": 2])
        }
        Task { await self.readLoop(conn, gen) }
        Task { await self.pingLoop(conn, gen) }
        if renew, let o = old { o.close() }
    }

    func sendRaw(_ frame: JSONObject) async throws {
        let w = lock.locked { ws }
        guard let socket = w, !socket.isClosed else {
            throw SkapiError("Realtime connection is not open. Try reconnecting with connectRealtime().", code: "INVALID_REQUEST")
        }
        try await socket.send(JSON.object(frame).jsonString)
    }

    private func pingLoop(_ conn: WebSocketConnection, _ gen: Int) async {
        var nextPing = Date()
        while current(gen) && !conn.isClosed {
            let now = Date()
            let (drop, renewNow, sendPing) = lock.locked { () -> (Bool, Bool, Bool) in
            var drop = false, renewNow = false, sendPing = false
            if let deadline = pongDeadline, now >= deadline {
                if now.timeIntervalSince(pingSentAt) > 30 {
                    pongDeadline = nil  // this task ran late: ping again instead
                    nextPing = now
                } else {
                    drop = true
                }
            }
            if !drop && now >= renewAt {
                renewAt = .distantFuture
                renewNow = true
            }
            if !drop && now >= nextPing {
                if pongSeen {
                    ponglessPings += 1
                    if ponglessPings >= RealtimeConnection.ponglessPingsDead { drop = true }
                    else if pongDeadline == nil {
                        pingSentAt = now
                        pongDeadline = now.addingTimeInterval(RealtimeConnection.pongTimeout)
                    }
                }
                if !drop { sendPing = true; nextPing = now.addingTimeInterval(RealtimeConnection.pingInterval) }
            }
            return (drop, renewNow, sendPing)
            }
            if drop { self.drop(conn, gen); return }
            if renewNow { Task { await self.renew(gen) } }
            if sendPing {
                do { try await conn.send("{\"action\":\"keepAlive\"}") } catch { return }
            }
            try? await Task.sleep(nanoseconds: 500_000_000)
        }
    }

    /// Asks a socket that looks open whether it is alive, now (the app came back to the foreground).
    func pingNow() {
        lock.lock()
        let conn = ws
        if conn != nil && pongSeen && pongDeadline == nil {
            pingSentAt = Date()
            pongDeadline = Date().addingTimeInterval(RealtimeConnection.pongTimeout)
        }
        lock.unlock()
        if let c = conn { Task { try? await c.send("{\"action\":\"keepAlive\"}") } }
    }

    private func renew(_ gen: Int) async {
        guard current(gen) else { return }
        try? await open(renew: true)  // on failure the old socket stays
    }

    private func drop(_ conn: WebSocketConnection, _ gen: Int) {
        guard current(gen) else { return }
        conn.close()
        emit(RealtimeEvent(type: "error", message: "Skapi: WebSocket unexpected close."))
        scheduleReconnect(gen)
    }

    func scheduleReconnect(_ gen: Int) {
        lock.lock()
        if reconnecting { lock.unlock(); return }
        reconnecting = true
        lock.unlock()
        Task {
            defer { self.lock.locked { self.reconnecting = false } }
            while self.current(gen) {
                guard let skapi = self.skapi, await skapi.signedIn() else {
                    self.emit(RealtimeEvent(type: "error", message: "Skapi: Realtime connection closed. User login is required."))
                    return
                }
                let attempts = self.lock.locked { () -> Int in
                    self.reconnectAttempts += 1
                    return self.reconnectAttempts
                }
                let base = min(30.0, 3.0 * pow(2, Double(attempts - 1)))
                self.emit(RealtimeEvent(type: "reconnect", message: .string("Reconnecting to WebSocket server...\(attempts)")))
                try? await Task.sleep(nanoseconds: UInt64(base * (1 + Double.random(in: 0..<0.5)) * 1_000_000_000))
                if !self.current(gen) { return }
                do {
                    if await skapi.isAnonymousUser, try await skapi.verifyAnonymousSession() == nil { continue }
                    try await self.open()
                    return
                } catch {
                    continue
                }
            }
        }
    }

    /// The app came back, or the network did: a closed socket reconnects now instead of at the end of its wait.
    func reconnectNowIfClosed() {
        lock.lock()
        let closedNow = !closing && (ws?.isClosed ?? true)
        let gen = generation
        lock.unlock()
        if closedNow {
            Task {
                guard self.current(gen), let skapi = self.skapi, await skapi.signedIn() else { return }
                try? await self.open()
            }
        } else {
            pingNow()
        }
    }

    private func readLoop(_ conn: WebSocketConnection, _ gen: Int) async {
        while true {
            let text: String
            do {
                text = try await conn.receive()
            } catch {
                if current(gen) {
                    emit(RealtimeEvent(type: "error", message: "Skapi: WebSocket unexpected close."))
                    scheduleReconnect(gen)
                } else {
                    let intentional = lock.locked { closing && gen == generation }
                    if intentional { emit(RealtimeEvent(type: "close", message: "WebSocket connection closed.")) }
                }
                return
            }
            lock.locked { pongDeadline = nil }
            if let data = try? JSON.parse(text), let o = data.object { await readFrame(o) }
        }
    }

    // ---- incoming frames -------------------------------------------------------------------------

    private static let presence: [String: [(String, String)]] = [
        "j": [("has joined the message group.", "USER_JOINED")],
        "l": [("has left the message group.", "USER_LEFT")],
        "d": [("has been disconnected.", "USER_DISCONNECTED"), ("has left the message group.", "USER_LEFT")],
    ]

    private func nonEmpty(_ v: JSON?) -> String? {
        guard let v = v, v.truthy else { return nil }
        return v.pyString
    }

    func readFrame(_ data: JSONObject) async {
        if data.contains("#pong") {
            lock.locked { pongSeen = true; ponglessPings = 0 }
            return
        }
        if let events = data["#presence"]?.array {
            let rid = nonEmpty(data["#srid"])
            for ev in events {
                guard let e = ev.array, let kind = e.first?.string, let texts = RealtimeConnection.presence[kind] else { continue }
                let uid = e.count > 1 ? e[1] : JSON.null
                let cid = e.count > 2 ? e[2] : JSON.null
                for (text, code) in texts {
                    await notice(RealtimeEvent(type: "notice", message: .string("User \"\(uid.pyString)\" \(text)"), sender: nonEmpty(uid),
                                               senderCid: nonEmpty(cid).map { "cid:\($0)" }, senderRid: rid, code: code))
                }
            }
            return
        }
        if let batch = data["#batch"]?.array {
            for entry in batch { if let o = entry.object { await readFrame(o) } }
            return
        }
        var kind: String?
        var payload: JSON = .null
        for (key, name) in [("#message", "message"), ("#private", "private"), ("#notice", "notice"), ("#rtc", "rtc"), ("#error", "error"), ("#ice", "ice")] {
            if let v = data[key] { kind = name; payload = v; break }
        }
        guard let k = kind, k != "rtc", k != "ice" else { return }
        let msg = RealtimeEvent(type: k, message: payload, sender: nonEmpty(data["#user_id"]), senderCid: nonEmpty(data["#scid"]).map { "cid:\($0)" },
                                senderRid: nonEmpty(data["#srid"]), code: nonEmpty(data["#code"]))
        if k == "notice" {
            await notice(msg)
        } else if k == "message", let s = data["#seq"]?.number, msg.senderCid != nil {
            inOrder(msg, Int(s))
        } else {
            deliver(msg)
        }
    }

    private func deliver(_ msg: RealtimeEvent) {
        if let batch = msg.message["__skapi_batch"]?.array {
            for item in batch { emit(msg.with(message: item)) }
        } else {
            emit(msg)
        }
    }

    private func notice(_ msg: RealtimeEvent) async {
        if msg.code == "USER_LEFT" || msg.code == "USER_DISCONNECTED", let cid = msg.senderCid { forgetOrder(cid) }
        let myId = await skapi?.currentUserId()
        lock.locked {
            if let w = _joinWait, msg.code == "USER_JOINED", msg.senderRid == w.group, msg.sender == myId {
                _joinWait?.signaled = true
            }
        }
        emit(msg)
    }

    // in-order delivery of a sender's numbered group messages (the fan-out can reorder them)
    private func inOrder(_ msg: RealtimeEvent, _ s: Int) {
        guard let cid = msg.senderCid else { return }
        var ready: [RealtimeEvent] = []
        lock.lock()
        var state = order[cid] ?? (next: s, waiting: [:], timer: nil)
        if s < state.next {
            ready = [msg]
        } else {
            state.waiting[s] = msg
            ready = drain(&state)
            if !state.waiting.isEmpty && state.timer == nil { state.timer = gapTimer(cid) }
        }
        order[cid] = state
        lock.unlock()
        for m in ready { deliver(m) }
    }

    private func drain(_ state: inout (next: Int, waiting: [Int: RealtimeEvent], timer: Task<Void, Never>?)) -> [RealtimeEvent] {
        var out: [RealtimeEvent] = []
        while let m = state.waiting.removeValue(forKey: state.next) {
            out.append(m)
            state.next += 1
        }
        return out
    }

    private func gapTimer(_ cid: String) -> Task<Void, Never> {
        Task {
            try? await Task.sleep(nanoseconds: UInt64(RealtimeConnection.seqWait * 1_000_000_000))
            if Task.isCancelled { return }
            self.skipGap(cid)
        }
    }

    private func skipGap(_ cid: String) {
        var ready: [RealtimeEvent] = []
        lock.lock()
        if var state = order[cid] {
            state.timer = nil
            if let lowest = state.waiting.keys.min() { state.next = lowest }
            ready = drain(&state)
            if !state.waiting.isEmpty { state.timer = gapTimer(cid) }
            order[cid] = state
        }
        lock.unlock()
        for m in ready { deliver(m) }
    }

    func forgetOrder(_ cid: String? = nil) {
        var ready: [RealtimeEvent] = []
        lock.lock()
        let cids = cid.map { [$0] } ?? Array(order.keys)
        for c in cids {
            if let state = order.removeValue(forKey: c) {
                state.timer?.cancel()
                ready += state.waiting.keys.sorted().map { state.waiting[$0]! }
            }
        }
        lock.unlock()
        for m in ready { deliver(m) }
    }

    // ---- outgoing group posts: posts within 100 ms travel as one frame, so they arrive in order ------

    func queueGroupPost(_ group: String, _ content: JSON, _ base: JSONObject) async {
        if lock.locked({ window.map { $0.group != group } ?? false }) { await flush() }
        enum Next { case queued, sendNow }
        let next: Next = lock.locked {
            if window != nil {
                window!.items.append(content)
                return .queued
            }
            let now = Date()
            let since = now.timeIntervalSince(lastSend[group] ?? .distantPast)
            lastSend[group] = now
            if since >= RealtimeConnection.sendWindow { return .sendNow }
            let timer = Task {
                try? await Task.sleep(nanoseconds: UInt64(RealtimeConnection.sendWindow * 1_000_000_000))
                if Task.isCancelled { return }
                await self.flush()
            }
            window = (group, [content], base, timer)
            return .queued
        }
        if next == .sendNow { await sendGroup(base, content) }
    }

    func flush() async {
        let taken = lock.locked { () -> (group: String, items: [JSON], base: JSONObject, timer: Task<Void, Never>)? in
            guard let w = window else { return nil }
            window = nil
            w.timer.cancel()
            lastSend[w.group] = Date()
            return w
        }
        guard let w = taken else { return }
        var items = w.items
        while !items.isEmpty {
            var n = items.count
            while n > 1 && JSON.object(["__skapi_batch": .array(Array(items[0..<n]))]).jsonString.utf16.count > RealtimeConnection.batchChars {
                n = (n + 1) / 2
            }
            await sendGroup(w.base, n == 1 ? items[0] : ["__skapi_batch": .array(Array(items[0..<n]))])
            items.removeFirst(n)
        }
    }

    func sendGroup(_ base: JSONObject, _ content: JSON) async {
        let s = lock.locked { () -> Int in
            let s = seq
            seq += 1
            return s
        }
        var frame = base
        frame["content"] = content
        frame["seq"] = .number(Double(s))
        try? await sendRaw(frame)  // not open at send time: dropped, as in skapi-js
    }

    func close() {
        lock.lock()
        closing = true
        window?.timer.cancel()
        window = nil
        let w = ws
        _joinWait?.signaled = true
        _room = nil
        lock.unlock()
        w?.close()
        forgetOrder()
    }
}

extension Skapi {
    func currentAccessToken() -> String? { sess?.accessToken.jwtToken }
    func currentUserId() -> String? { userObj?["user_id"]?.string }
    var isAnonymousUser: Bool { isAnonymous }

    /// Opens the realtime connection. The callback runs on a background task for every message,
    /// notice and connection event (hop to the main actor for UI work). Returns once connected;
    /// reconnects on its own.
    public func connectRealtime(_ callback: @escaping @Sendable (RealtimeEvent) -> Void) async throws {
        try await ensureConnection()
        if !(await signedIn()) { throw SkapiError("No access.", code: "INVALID_REQUEST") }
        if let r = rt, !r.isClosing {
            r.setCallback(callback)
            return
        }
        let r = RealtimeConnection(skapi: self, callback: callback)
        rt = r
        do {
            try await r.open()
        } catch {
            if rt === r { rt = nil }
            r.emit(RealtimeEvent(type: "error", message: "Skapi: WebSocket connection failed."))
            throw error
        }
    }

    /// Closes the realtime connection; the group hears that you disconnected and left.
    public func closeRealtime() {
        let r = rt
        rt = nil
        r?.close()
    }

    private func live() throws -> RealtimeConnection {
        guard let r = rt, !r.isClosing else {
            throw SkapiError("No realtime connection. Execute connectRealtime() before this method.", code: "INVALID_REQUEST")
        }
        return r
    }

    /// Joins a message group (one at a time), or leaves the current one with nil.
    @discardableResult
    public func joinRealtime(group: String?) async throws -> JSON {
        let r = try live()
        let g = (group?.isEmpty ?? true) ? nil : group
        if g == nil && r.room == nil { return ["type": "success", "message": "Left realtime message group."] }
        let token = try await accessToken()
        r.joinWaitState?.signaled = true
        if r.isOpen {
            try await r.sendRaw(["action": "joinRoom", "rid": JSON(g), "token": .string(token), "ver": 2])
            if let gg = g { r.joinWaitState = (gg, Date().addingTimeInterval(RealtimeConnection.joinWait), false) }
        }
        r.room = g
        return ["type": "success", "message": .string(g.map { "Joined realtime message group: \"\($0)\"." } ?? "Left realtime message group.")]
    }

    /// Sends to a user (by user ID) or to the group you joined.
    /// notification: ["title", "body", "config"?: ["always": Bool]].
    @discardableResult
    public func postRealtime(_ message: JSON, recipient: String, notification: JSON? = nil) async throws -> JSON {
        let r = try live()
        if recipient.isEmpty { throw SkapiError("No recipient.", code: "INVALID_REQUEST") }
        _ = try await freshIdToken()
        var notificationStr = ""
        var config: JSON = .object(JSONObject())
        if let n = notification, !n.isNull {
            guard let no = n.object else { throw paramError("\"notification\" should be an object with \"title\" and \"body\".") }
            for key in ["title", "body"] {
                guard let v = no[key] else { throw paramError("Key \"\(key)\" is required.") }
                if !v.isString { throw paramError("\"\(key)\" should be type: <string>.") }
            }
            config = no["config"].truthy ? no["config"]! : .object(JSONObject())
            if !config.isObject || (config["always"] != nil && !(config["always"]!.isBool)) {
                throw paramError("\"config.always\" should be type: <boolean>.")
            }
            notificationStr = JSON.object(["title": no["title"]!, "body": no["body"]!]).jsonString
            if notificationStr.utf8.count > RealtimeConnection.maxNotificationBytes { throw paramError("Notification size exceeds 3kb.") }
        }
        if !r.isOpen { throw SkapiError("Realtime connection is not open. Try reconnecting with connectRealtime().", code: "INVALID_REQUEST") }
        let token = "IdT:\(service):\(owner):\(sess?.idToken.jwtToken ?? "")"

        func checked(_ frame: JSONObject) throws -> JSONObject {
            let size = JSON.object(frame).jsonString.utf8.count
            if size > RealtimeConnection.maxFrameBytes {
                throw paramError("Message is \(size) bytes; a realtime message can be at most \(RealtimeConnection.maxFrameBytes) bytes including its headers.")
            }
            return frame
        }

        if Check.isUUID(recipient) {
            try await r.sendRaw(try checked(["action": "sendMessage", "uid": .string(recipient), "content": message, "notification": .string(notificationStr),
                                             "notificationConfig": config, "token": .string(token)]))
            return ["type": "success", "message": "Message sent."]
        }
        if recipient != r.room {
            throw SkapiError("User has not joined to the recipient group. Run joinRealtime(group: \"\(recipient)\")", code: "INVALID_REQUEST")
        }
        _ = try checked(["action": "broadcast", "rid": .string(recipient), "content": message, "notification": .string(notificationStr),
                         "notificationConfig": config, "token": .string(token), "#seq": 0])
        // until the server announces your own join, the group would not get the message yet
        while let w = r.joinWaitState, w.group == recipient, !w.signaled, Date() < w.until {
            try? await Task.sleep(nanoseconds: 50_000_000)
        }
        if let w = r.joinWaitState, w.group == recipient { r.joinWaitState = nil }
        let base: JSONObject = ["action": "broadcast", "rid": .string(recipient), "notification": .string(notificationStr),
                                "notificationConfig": config, "token": .string(token)]
        if notification != nil && !(notification!.isNull) {
            await r.sendGroup(base, message)  // a post with a notification is never grouped
        } else {
            await r.queueGroupPost(recipient, message, base)
        }
        return ["type": "success", "message": "Message sent."]
    }

    /// Who is connected in a group (default: the group you joined): [["user_id", "cid"]].
    public func getRealtimeUsers(_ params: JSON? = nil, fetchOptions: FetchOptions? = nil) async throws -> JSON {
        let p = params?.object ?? JSONObject()
        var body = JSONObject()
        if let g = p["group"] {
            guard g.isString else { throw paramError("\(jd(g)) is invalid in \"group\". allowed type or value is: Type<string>.") }
            body["group"] = g
        } else {
            guard let room = rt?.room, !room.isEmpty else { throw paramError("No group has been joined. Otherwise \"group\" is required.") }
            body["group"] = .string(room)
        }
        if p.contains("user_id") { body["user_id"] = .string(try DB.userId(p["user_id"], "User ID in \"user_id\"")) }
        var res = try await call("get-ws-group", .object(body), auth: true, fetchOptions: fetchOptions?.object)
        if let list = res["list"]?.array {
            res["list"] = .array(list.map { i in
                let uid = i["uid"]?.pyString ?? ""
                return ["user_id": uid.contains("#") ? .string(uid.components(separatedBy: "#")[1]) : (i["uid"] ?? .null),
                        "cid": .string("cid:\(i["cid"]?.pyString ?? "None")")]
            })
        }
        return res
    }

    /// Groups that have members now: [["group", "number_of_users"]].
    public func getRealtimeGroups(_ params: JSON? = nil, fetchOptions: FetchOptions? = nil) async throws -> JSON {
        try await ensureConnection()
        var p = params?.object ?? JSONObject()
        if p.isEmpty { p = ["searchFor": "group", "value": " ", "condition": ">"] }
        let searchFor = p["searchFor"] ?? "group"
        guard let sf = searchFor.string, sf == "group" || sf == "number_of_users" else {
            throw paramError("\(jd(searchFor)) is invalid in \"searchFor\". allowed types or values are: \"group\", \"number_of_users\".")
        }
        let value = p["value"] ?? (sf == "number_of_users" ? 0 : " ")
        let conditions = [">", ">=", "=", "<", "<=", "!=", "gt", "gte", "eq", "lt", "lte", "ne"]
        var condition: String?
        if let c = p["condition"], !c.isNull {
            guard let cs = c.string, conditions.contains(cs) else {
                throw paramError("\(jd(c)) is invalid in \"condition\". allowed types or values are: " + conditions.map { jd(.string($0)) }.joined(separator: ", ") + ".")
            }
            condition = cs
        } else {
            condition = (value == .string(" ") || !value.truthy) ? ">" : "="
        }
        var body: JSONObject = ["searchFor": .string(sf), "value": value]
        if let r = p["range"], !r.isNull {
            body["range"] = r
            condition = nil
        }
        if sf == "number_of_users" && !value.isNumber { throw paramError("\"value\" must be a number.") }
        if sf == "group" && !value.isString { throw paramError("\"value\" must be a string.") }
        if let r = body["range"], DB.typeOf(r) != DB.typeOf(value) { throw paramError("\"range\" must be a \(value.isNumber ? "number" : "string").") }
        if let c = condition { body["condition"] = .string(c) }
        var res = try await call("get-ws-group", .object(body), auth: true, fetchOptions: fetchOptions?.object)
        if let list = res["list"]?.array {
            res["list"] = .array(list.map { i in
                let rid = i["rid"]?.pyString ?? ""
                return ["group": rid.contains("#") ? .string(rid.components(separatedBy: "#")[1]) : (i["rid"] ?? .null), "number_of_users": i["cnt"] ?? .null]
            })
        }
        return res
    }
}
