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
        .package(url: "https://github.com/TICESoftware/swift-sodium.git", from: "0.9.2"),
        .package(url: "https://github.com/TICESoftware/HKDF.git", from: "1.0.10"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.0.0"),
    ],
    targets: [
        .target(
            name: "DoubleRatchet",
            dependencies: ["Sodium", "HKDF", "Logging"]),
        .testTarget(
            name: "DoubleRatchetTests",
            dependencies: ["DoubleRatchet", "Sodium"]),
    ]
)
