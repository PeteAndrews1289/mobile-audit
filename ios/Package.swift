// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "MobileAuditCore",
    platforms: [.iOS(.v17), .macOS(.v13)],
    products: [.library(name: "MobileAuditCore", targets: ["MobileAuditCore"])],
    targets: [
        .target(name: "MobileAuditCore", path: "Sources/MobileAuditCore"),
        .testTarget(
            name: "MobileAuditCoreTests",
            dependencies: ["MobileAuditCore"],
            path: "Tests/MobileAuditCoreTests",
            resources: [.copy("Fixtures/sample.ndjson")]
        ),
    ]
)
