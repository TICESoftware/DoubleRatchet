// swift-tools-version:5.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "DoubleRatchet",
    products: [
        .library(
            name: "DoubleRatchet",
            targets: ["DoubleRatchet"]),
    ],
    dependencies: [
        .package(url: "https://github.com/TICESoftware/swift-sodium.git", .branch("spmWorkaround")),
        .package(url: "https://github.com/TICESoftware/Clibsodium.git", from: "1.0.1"),
        .package(url: "https://github.com/TICESoftware/HKDF.git",  .branch("explicitClibsodium")),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.0.0"),
    ],
    targets: [
        .target(
            name: "DoubleRatchet",
            dependencies: ["Sodium", "HKDF", "Logging", "Clibsodium"]),
        .testTarget(
            name: "DoubleRatchetTests",
            dependencies: ["DoubleRatchet", "Sodium", "Clibsodium"]),
    ]
)
