// Compiles the tiny Objective-C shim that installs an AppleEvent handler
// for the `x-splitwg://` URL scheme. Kept as a .m file (not Rust through
// objc2) because `NSAppleEventManager::setEventHandler:andSelector:…`
// requires a real ObjC selector on a real NSObject instance, and a shim
// is dramatically less fragile than declaring a custom class via
// `objc2::define_class!`.

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    cc::Build::new()
        .file("src/gui/url_handler_bridge.m")
        .flag("-fobjc-arc")
        .compile("url_handler_bridge");
    println!("cargo:rerun-if-changed=src/gui/url_handler_bridge.m");
    println!("cargo:rustc-link-lib=framework=AppKit");
    println!("cargo:rustc-link-lib=framework=Foundation");
}
