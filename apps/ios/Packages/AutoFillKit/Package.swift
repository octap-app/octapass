// swift-tools-version: 5.9
// What the AutoFill Credential Provider extension does, apart from its screens: open the shared
// store, unlock it, find logins, passkeys and one-time codes, and answer the system's requests.
// Tested on the Mac against the core's in-process TestServer: run
// apps/ios/scripts/test-packages.sh (it builds the core's test flavour first).
import PackageDescription

let package = Package(
    name: "OctaPassAutoFillKit",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "OctaPassAutoFillKit", targets: ["OctaPassAutoFillKit"]),
    ],
    dependencies: [
        .package(path: "../Keychain"),
        .package(path: "../OctaPassCore"),
    ],
    targets: [
        .target(
            name: "OctaPassAutoFillKit",
            dependencies: [
                .product(name: "OctaPassKeychain", package: "Keychain"),
                .product(name: "OctaPassCore", package: "OctaPassCore"),
            ]
        ),
        .testTarget(name: "OctaPassAutoFillKitTests", dependencies: ["OctaPassAutoFillKit"]),
    ]
)
