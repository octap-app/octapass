// swift-tools-version: 6.0
// Octa Pass strings and design tokens for the iOS app, generated from the web vault's catalogs and
// packages/ui's tokens by tools/native-resources. Only this file and the tests are written by hand.

import PackageDescription

let package = Package(
    name: "OctaPassResources",
    defaultLocalization: "en",
    platforms: [.iOS(.v17), .watchOS(.v10), .macOS(.v14)],
    products: [
        .library(name: "OctaPassResources", targets: ["OctaPassResources"]),
    ],
    targets: [
        .target(name: "OctaPassResources", resources: [.process("Resources")]),
        .testTarget(name: "OctaPassResourcesTests", dependencies: ["OctaPassResources"], resources: [.process("Resources")]),
    ]
)
