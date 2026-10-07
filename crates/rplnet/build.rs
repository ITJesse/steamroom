fn main() {
    // Target triple of this build, reported by `rplnet_version()` so the app
    // log shows which slice of the xcframework is running.
    println!(
        "cargo:rustc-env=RPLNET_TARGET={}",
        std::env::var("TARGET").expect("cargo sets TARGET for build scripts")
    );
}
