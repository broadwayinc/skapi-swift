// swift-tools-version:5.9
//
// skapi-swift: the Skapi backend for iOS and macOS. Sign users in, keep their sessions, and read
// and write your project's database with the same API as skapi-js.
//
// On Apple platforms the package uses only the system frameworks (Foundation, CryptoKit,
// CommonCrypto, Security). swift-crypto is linked on Linux only, where CryptoKit does not exist.

import PackageDescription

let package = Package(
    name: "Skapi",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
    ],
    products: [
        .library(name: "Skapi", targets: ["Skapi"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"5.0.0"),
    ],
    targets: [
        .target(
            name: "Skapi",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto", condition: .when(platforms: [.linux])),
            ]
        ),
        // Offline checks of record decoding (`swift test`). No network calls.
        .testTarget(name: "SkapiTests", dependencies: ["Skapi"]),
    ],
    swiftLanguageVersions: [.v5]
)
