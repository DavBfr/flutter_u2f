// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to
// build this package.

import PackageDescription

let package = Package(
  name: "u2f",
  platforms: [
    .macOS("12.0")
  ],
  products: [
    .library(name: "u2f", targets: ["u2f"])
  ],
  dependencies: [
    .package(name: "FlutterFramework", path: "../FlutterFramework"),
    // hidapi is vendored (see hidapi/README.md) so this package is
    // self-contained and builds offline, with no external dependency.
    .package(name: "hidapi", path: "hidapi")
  ],
  targets: [
    .target(
      name: "u2f",
      dependencies: [
        .product(name: "FlutterFramework", package: "FlutterFramework"),
        .product(name: "hidapi", package: "hidapi")
      ],
      path: "Sources/u2f",
      publicHeadersPath: "include",
      cSettings: [
        .headerSearchPath("include")
      ],
      linkerSettings: [
        // Dart resolves the hidapi symbols from the process image when the
        // plugin is linked statically (Swift Package Manager). This root keeps
        // the symbol table and the hidapi objects in the final binary, so they
        // survive dead-stripping in release builds.
        .unsafeFlags(["-Wl,-u,_u2f_hidapi_symbols"])
      ]
    )
  ]
)
