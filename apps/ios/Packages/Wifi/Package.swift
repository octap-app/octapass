// swift-tools-version: 5.9
// The Wi-Fi logic of the app's Tauri plugin that doesn't need a device: what the web view sends to
// join a network, the location permission as the web view names it, and network names as iOS
// reports them. Kept apart from the plugin so it's tested on the Mac (`swift test`).
import PackageDescription

let package = Package(
    name: "OctaPassWifi",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "OctaPassWifi", targets: ["OctaPassWifi"]),
    ],
    targets: [
        .target(name: "OctaPassWifi"),
        .testTarget(name: "OctaPassWifiTests", dependencies: ["OctaPassWifi"]),
    ]
)
