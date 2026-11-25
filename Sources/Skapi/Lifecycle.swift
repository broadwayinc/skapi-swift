import Foundation
#if canImport(UIKit)
import UIKit
#endif
#if canImport(AppKit)
import AppKit
#endif
#if canImport(Network)
import Network
#endif

/// Watches the app coming back to the foreground and the network coming back, the native
/// counterparts of the browser's "visibilitychange" and "online" events skapi-js listens to.
final class LifecycleObserver: @unchecked Sendable {
    private var tokens: [NSObjectProtocol] = []
    #if canImport(Network)
    private var monitor: NWPathMonitor?
    private var wasSatisfied = true
    #endif

    init(onReturn: @escaping @Sendable () -> Void) {
        let center = NotificationCenter.default
        #if canImport(UIKit) && !os(watchOS)
        tokens.append(center.addObserver(forName: UIApplication.willEnterForegroundNotification, object: nil, queue: nil) { _ in onReturn() })
        #elseif canImport(AppKit)
        tokens.append(center.addObserver(forName: NSApplication.didBecomeActiveNotification, object: nil, queue: nil) { _ in onReturn() })
        #endif
        #if canImport(Network)
        let m = NWPathMonitor()
        m.pathUpdateHandler = { [weak self] path in
            guard let self = self else { return }
            let ok = path.status == .satisfied
            if ok && !self.wasSatisfied { onReturn() }
            self.wasSatisfied = ok
        }
        m.start(queue: DispatchQueue(label: "skapi.network"))
        monitor = m
        #endif
        _ = center
    }

    deinit {
        for t in tokens { NotificationCenter.default.removeObserver(t) }
        #if canImport(Network)
        monitor?.cancel()
        #endif
    }
}

extension Skapi {
    func startLifecycleIfNeeded() {
        guard observeAppLifecycle, lifecycle == nil else { return }
        lifecycle = LifecycleObserver { [weak self] in
            guard let skapi = self else { return }
            Task { await skapi.appDidReturn() }
        }
    }

    /// Call this when your app comes back to the foreground, if you created the Skapi object with
    /// `observeAppLifecycle: false` (it is called on its own otherwise). A realtime connection that
    /// died meanwhile reconnects at once, one that looks open is asked whether it is alive, and an
    /// anonymous account is checked so a deleted one is signed out right away.
    public func appDidReturn() async {
        rt?.reconnectNowIfClosed()
        await recheckAnonymousSession()
    }
}
