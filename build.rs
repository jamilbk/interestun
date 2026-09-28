fn main() {
    println!("cargo:rerun-if-changed=src/platform/network_flow.m");
    if std::env::var_os("CARGO_FEATURE_APPLE_NETWORK").is_some()
        && std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos")
    {
        let mut build = cc::Build::new();
        build.file("src/platform/network_flow.m");
        if std::env::var_os("CARGO_FEATURE_APPLE_NETWORK_MULTIPLE").is_some() {
            build.define("IN_NETWORK_MULTIPLE", None);
        }
        if std::env::var_os("CARGO_FEATURE_NETWORK_BENCH").is_some() {
            build.define("IN_NETWORK_BENCH", None);
        }
        build
            .flag("-fobjc-arc")
            .flag("-fblocks")
            .flag("-Wall")
            .flag("-Wextra")
            .flag("-Werror")
            .compile("interestun_apple_network");
        println!("cargo:rustc-link-lib=framework=Network");
        println!("cargo:rustc-link-lib=framework=Foundation");
    }
}
