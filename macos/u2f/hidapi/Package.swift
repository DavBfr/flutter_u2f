// swift-tools-version: 5.9

import PackageDescription

let package = Package(
  name: "hidapi_internal",
  platforms: [
    .macOS("10.14")
  ],
  products: [
    .library(name: "hidapi", targets: ["hidapi"])
  ],
  targets: [
    .target(
      name: "hidapi",
      path: "Sources/hidapi",
      publicHeadersPath: "include",
      cSettings: [
        .headerSearchPath("include"),
        .headerSearchPath("include/hidapi"),
      ]
    )
  ]
)
