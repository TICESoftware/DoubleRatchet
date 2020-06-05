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
        .package(url: "https://github.com/jedisct1/swift-sodium", from: "0.8.0"),
        .package(url: "https://github.com/TICESoftware/HKDF.git", from: "1.0.4"),
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
