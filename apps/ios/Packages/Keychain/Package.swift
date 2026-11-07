// swift-tools-version: 5.9
// What the Octa Pass app and its AutoFill and Files extensions share on the device: Keychain items
// (the Secret Key, the refresh token, the device-unlock secret behind Face ID / Touch ID or the
// passcode, the open Safes' keys for the Files extension) and the App Group container. No dependency on the core, so the app's Tauri plugin
// can use it without linking the core a second time.
import PackageDescription

let package = Package(
    name: "OctaPassKeychain",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "OctaPassKeychain", targets: ["OctaPassKeychain"]),
    ],
    targets: [
        .target(name: "OctaPassKeychain"),
        .testTarget(name: "OctaPassKeychainTests", dependencies: ["OctaPassKeychain"]),
    ]
)
