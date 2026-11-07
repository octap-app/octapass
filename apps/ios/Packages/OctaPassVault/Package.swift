// swift-tools-version: 5.9
// OctaPassVault: the vault API the native iPhone and iPad app is built on (plan 17), generated
// from crates/octapass-mobile.
//
// Build the XCFramework and regenerate Sources/OctaPassVault with
// crates/octapass-mobile/scripts/build-ios.sh. The tests run on this Mac against a host build
// of the library and the real sync server: crates/octapass-mobile/scripts/test-swift.sh builds
// it into .testing/ and sets OCTAPASS_VAULT_TESTING=1.
import PackageDescription

let testing = Context.environment["OCTAPASS_VAULT_TESTING"] == "1"
let framework = (testing ? ".testing/" : "") + "OctaPassVaultFFI.xcframework"

let package = Package(
    name: "OctaPassVault",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "OctaPassVault", targets: ["OctaPassVault"]),
    ],
    targets: [
        .binaryTarget(name: "OctaPassVaultFFI", path: framework),
        .target(
            name: "OctaPassVault",
            dependencies: ["OctaPassVaultFFI"],
            linkerSettings: [.linkedFramework("Security"), .linkedFramework("SystemConfiguration")]
        ),
        .testTarget(name: "OctaPassVaultTests", dependencies: ["OctaPassVault"]),
    ]
)
