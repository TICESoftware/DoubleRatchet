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
    ],
    targets: [
        .target(
            name: "DoubleRatchet",
            dependencies: []),
        .testTarget(
            name: "DoubleRatchetTests",
            dependencies: ["DoubleRatchet"]),
    ]
)
