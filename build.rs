use std::{env, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=RPTADV_CODEC_INCLUDE");
    let include =
        env::var("RPTADV_CODEC_INCLUDE").unwrap_or_else(|_| "/usr/include/rptadv-codec".to_owned());
    let header = PathBuf::from(include).join("rptadv_codec.h");
    println!("cargo:rerun-if-changed={}", header.display());
    bindgen::Builder::default()
        .header(header.to_string_lossy())
        .allowlist_type("rptadv_codec_.*")
        .allowlist_var("RPTADV_CODEC_.*")
        .derive_default(true)
        .layout_tests(false)
        .generate_comments(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("generate installed neutral codec ABI")
        .write_to_file(PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("codec_abi.rs"))
        .expect("write neutral codec ABI bindings");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,librptadviax2.so.1");
    }
}
