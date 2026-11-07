// swift-tools-version: 5.9
// The Octa Pass core for the iOS app and its AutoFill extension.
//
// Build the XCFramework and regenerate Sources/OctaPassCore with
// crates/octapass-ffi/scripts/build-ios.sh. The tests need the host test flavour of the library
// (it adds the in-process TestServer): run crates/octapass-ffi/scripts/test-swift.sh, which
// builds it into .testing/ and sets OCTAPASS_FFI_TESTING=1.
import PackageDescription

let testing = Context.environment["OCTAPASS_FFI_TESTING"] == "1"
let root = testing ? ".testing/" : ""

let package = Package(
    name: "OctaPassCore",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "OctaPassCore", targets: ["OctaPassCore"]),
    ],
    targets: [
        .binaryTarget(name: "OctaPassCoreFFI", path: root + "OctaPassCoreFFI.xcframework"),
        .target(
            name: "OctaPassCore",
            dependencies: ["OctaPassCoreFFI"],
            path: root + "Sources/OctaPassCore"
        ),
        .testTarget(name: "OctaPassCoreTests", dependencies: ["OctaPassCore"]),
    ]
)
