// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SecureAttest",
    platforms: [.iOS(.v15)],
    products: [
        .library(name: "SecureAttest", targets: ["SecureAttest"]),
        .library(name: "SecureAttestSupabase", targets: ["SecureAttestSupabase"]),
    ],
    dependencies: [
        .package(url: "https://github.com/securing/IOSSecuritySuite.git", from: "1.9.0"),
        .package(url: "https://github.com/supabase/supabase-swift.git", from: "2.0.0"),
    ],
    targets: [
        .target(
            name: "SecureAttest",
            dependencies: [
                .product(name: "IOSSecuritySuite", package: "IOSSecuritySuite"),
            ]
        ),
        .target(
            name: "SecureAttestSupabase",
            dependencies: [
                "SecureAttest",
                .product(name: "Supabase", package: "supabase-swift"),
            ]
        ),
        .testTarget(
            name: "SecureAttestTests",
            dependencies: ["SecureAttest"]
        ),
    ]
)
