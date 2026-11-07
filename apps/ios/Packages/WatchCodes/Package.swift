// swift-tools-version: 5.9
// What the Apple Watch app does with the codes the phone sends: reading a bundle and picking the
// code for this moment. No one-time code math: the codes are made in the Rust core on the phone
// (`crates/octapass-mobile/src/watch.rs`). No platform dependency, so `swift test` runs on a Mac.
import PackageDescription

let package = Package(
    name: "OctaPassWatchCodes",
    platforms: [.iOS(.v17), .watchOS(.v10), .macOS(.v14)],
    products: [
        .library(name: "OctaPassWatchCodes", targets: ["OctaPassWatchCodes"]),
    ],
    targets: [
        .target(name: "OctaPassWatchCodes"),
        .testTarget(name: "OctaPassWatchCodesTests", dependencies: ["OctaPassWatchCodes"]),
    ]
)
