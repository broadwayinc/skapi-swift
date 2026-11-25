import Foundation

// Shared pieces of skapi-js 2.7.0's transport rules: which failures a poll survives, how long it
// waits after them, request deadlines, and a sleep that a status frame can cut short.

/// Milliseconds on a clock that never goes back (the system uptime), for throttles and backoff. The
/// wall clock can jump back, and a throttle measured on it would skip reads until it caught up.
func monoMs() -> Double { ProcessInfo.processInfo.systemUptime * 1000 }

/// Codes of a request that failed on the way, not because the server said no (skapi-js 2.7.0): no
/// network, no answer in time, rate limited, a server fault, or a request aborted on its way out.
let transportFailureCodes: Set<String> = ["NETWORK_ERROR", "TIMEOUT", "RATE_LIMITED", "TOO_MANY_REQUESTS", "SERVER_ERROR", "ABORTED"]

func isTransportFailure(_ error: Error) -> Bool {
    guard let e = error as? SkapiError else { return false }
    return e.isTokenFailure || transportFailureCodes.contains(e.code)
}

/// The gateway refused the sign-in token (401).
func isUnauthorized(_ error: Error) -> Bool {
    (error as? SkapiError)?.code == "401"
}

/// Longest wait between two tries of a poll whose reads keep failing on the way.
let pollRetryMaxMs: Double = 30 * 1000

/// How long a poll waits after `failures` reads in a row failed on the way: the next tick after the
/// first, then twice the interval each time, up to pollRetryMaxMs.
func pollRetryDelay(_ latency: Double, _ failures: Int) -> Double {
    if failures <= 1 { return 0 }
    return min(pollRetryMaxMs, latency * pow(2, Double(failures - 1)))
}

/// SkapiError code ABORTED: the calling Task was cancelled (skapi-js 2.7.0 `signal`).
func abortedError() -> SkapiError { SkapiError("Aborted", code: "ABORTED", cause: CancellationError()) }

/// One continuation that whichever settles first resumes: the task, the timer, or a cancel. A cancel
/// that lands before the continuation is stored ends the wait as soon as it is.
private final class RaceSlot<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var cont: CheckedContinuation<T, Error>?
    private var early: Result<T, Error>?
    private var done = false

    func store(_ c: CheckedContinuation<T, Error>) {
        let r: Result<T, Error>? = lock.locked {
            if let e = early { early = nil; return e }
            cont = c
            return nil
        }
        if let r = r { c.resume(with: r) }
    }

    func settle(_ r: Result<T, Error>) {
        let c: CheckedContinuation<T, Error>? = lock.locked {
            if done { return nil }
            done = true
            guard let c = cont else { early = r; return nil }
            cont = nil
            return c
        }
        c?.resume(with: r)
    }
}

/// The value of `task`, or `timeoutError` once `seconds` pass first (no limit when nil). Cancelling the
/// calling Task ends the wait at once with ABORTED. The task itself is left running (the caller
/// decides whether to cancel it).
func raceTimeout<T: Sendable>(seconds: Double?, _ task: Task<T, Error>, timeoutError: SkapiError) async throws -> T {
    let slot = RaceSlot<T>()
    var timer: Task<Void, Never>?
    if let seconds = seconds {
        timer = Task {
            try? await Task.sleep(nanoseconds: UInt64(max(0, seconds) * 1_000_000_000))
            if Task.isCancelled { return }
            slot.settle(.failure(timeoutError))
        }
    }
    let waiter = Task {
        do { slot.settle(.success(try await task.value)) } catch { slot.settle(.failure(error)) }
    }
    defer {
        timer?.cancel()
        waiter.cancel()
    }
    return try await withTaskCancellationHandler {
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<T, Error>) in slot.store(c) }
    } onCancel: {
        slot.settle(.failure(abortedError()))
    }
}

/// Runs `op` with a deadline in milliseconds (skapi-js 2.7.0 `deadline`): past it the call fails with
/// TIMEOUT and its request is cancelled. Cancelling the calling Task cancels it too (ABORTED).
func withDeadline<T: Sendable>(_ ms: Double?, _ op: @escaping @Sendable () async throws -> T) async throws -> T {
    guard let ms = ms else { return try await op() }
    let task = Task { try await op() }
    return try await withTaskCancellationHandler {
        do {
            return try await raceTimeout(seconds: ms / 1000, task,
                                         timeoutError: SkapiError("No answer within \(formatMs(ms)) ms.", code: "TIMEOUT"))
        } catch {
            task.cancel()
            throw error
        }
    } onCancel: {
        task.cancel()
    }
}

private func formatMs(_ ms: Double) -> String {
    ms == ms.rounded() && abs(ms) < 1e15 ? String(Int64(ms)) : String(ms)
}

/// The transport options a read takes (skapi-js 2.7.0 readTransportOptions): `deadline`
/// (milliseconds above 0) and `fresh` (a boolean). `fresh` is accepted for parity with skapi-js and
/// changes nothing here: skapi-swift never joins a read to another one already in flight, so every
/// read is fresh. skapi-js's `signal` is the calling Task's cancellation (code ABORTED).
func readTransportOptions(_ o: JSONObject) throws -> Double? {
    var deadline: Double?
    if let d = o["deadline"], !d.isNull {
        guard let n = d.number, n.isFinite, n > 0 else { throw paramError("\"deadline\" should be a number of milliseconds above 0.") }
        deadline = n
    }
    if let f = o["fresh"], !f.isNull, !f.isBool { throw paramError("\"fresh\" should be type: <boolean>.") }
    return deadline
}

/// A sleep that `wake()` cuts short: a status frame naming the request, read at once. A wake while
/// nobody sleeps is kept for the next sleep. Cancelling the Task ends the sleep with CancellationError.
final class WakeSignal: @unchecked Sendable {
    private let lock = NSLock()
    private var pending = false
    private var cancelled = false
    private var waiter: (id: Int, cont: CheckedContinuation<Bool, Never>)?
    private var timer: Task<Void, Never>?
    private var nextId = 0

    func wake() {
        let c: CheckedContinuation<Bool, Never>? = lock.locked {
            guard let w = waiter else { pending = true; return nil }
            waiter = nil
            timer?.cancel()
            timer = nil
            return w.cont
        }
        c?.resume(returning: true)
    }

    /// Forgets a wake that arrived meanwhile.
    func clear() { lock.locked { pending = false } }

    /// Sleeps `ms` milliseconds; true when woken early.
    func sleep(ms: Double) async throws -> Bool {
        try Task.checkCancellation()
        let woken: Bool = await withTaskCancellationHandler {
            await withCheckedContinuation { (c: CheckedContinuation<Bool, Never>) in
                let resumeNow: Bool? = lock.locked {
                    if cancelled { return false }
                    if pending { pending = false; return true }
                    nextId += 1
                    let id = nextId
                    waiter = (id, c)
                    timer = Task { [weak self] in
                        try? await Task.sleep(nanoseconds: UInt64(max(0, ms) * 1_000_000))
                        if Task.isCancelled { return }
                        self?.finish(id)
                    }
                    return nil
                }
                if let r = resumeNow { c.resume(returning: r) }
            }
        } onCancel: {
            let c: CheckedContinuation<Bool, Never>? = lock.locked {
                cancelled = true
                let w = waiter
                waiter = nil
                timer?.cancel()
                timer = nil
                return w?.cont
            }
            c?.resume(returning: false)
        }
        try Task.checkCancellation()
        return woken
    }

    private func finish(_ id: Int) {
        let c: CheckedContinuation<Bool, Never>? = lock.locked {
            guard let w = waiter, w.id == id else { return nil }
            waiter = nil
            timer = nil
            return w.cont
        }
        c?.resume(returning: false)
    }
}
