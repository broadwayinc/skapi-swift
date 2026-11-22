# Skapi for Swift

The [Skapi](https://www.skapi.com) backend for iOS and macOS: sign users in, keep their sessions, and read and write your project's database. Same API as [skapi-js](https://www.npmjs.com/package/skapi-js) and skapi-py, in Swift style with async/await.

## Install

Swift Package Manager. In Xcode: File > Add Package Dependencies, then add the package and the `Skapi` library. In a `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/broadwayinc/skapi-swift.git", from: "2.4.4"),
],
targets: [
    .target(name: "MyApp", dependencies: [.product(name: "Skapi", package: "skapi-swift")]),
]
```

Requires iOS 15 or macOS 12, and Swift 5.9 or later.

## Use

```swift
import Skapi

let skapi = try Skapi(projectId: "<Project ID>")  // from your project's Settings page on skapi.com

try await skapi.login(email: "user@example.com", password: "password")

let record = try await skapi.postRecord(["title": "Hello"],
                                        config: ["table": ["name": "posts", "access_group": "public"]])
let posts = try await skapi.getRecords(["table": ["name": "posts", "access_group": "public"]])
for post in posts["list"]?.array ?? [] {
    print(post["data"]?["title"]?.string ?? "")
}
```

- No third-party dependencies on Apple platforms: Foundation, CryptoKit, CommonCrypto and Security only.
- Sign-in uses the same SRP exchange as skapi-js: the password never leaves the device.
- The session is kept in the Keychain between launches (or any storage you plug in).
- Two-step login with an authenticator app, file attachments, and every query form of skapi-js.
- Realtime messages between users, in groups or one to one, over a WebSocket that reconnects when the app comes back to the foreground.
- Optional encryption of private records on the device, compatible with skapi-js and skapi-py, with "remember this device" through the Keychain.

Documentation: https://ios.skapi.com

## License

Apache-2.0. Copyright broadway Inc.
