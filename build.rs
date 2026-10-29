use std::{env, path::PathBuf};

fn main() {
    let init = env::var_os("CARGO_FEATURE_EMBEDDED_INIT").is_some();
    let dotnet = env::var_os("CARGO_FEATURE_EMBEDDED_DOTNET").is_some();
    assert!(
        !(init && dotnet),
        "select only one embedded deployment flavor"
    );
    for name in ["TINYVMM_KERNEL", "TINYVMM_INITRD"] {
        println!("cargo:rerun-if-env-changed={name}");
        if init || dotnet {
            let path = PathBuf::from(env::var_os(name).unwrap_or_else(|| {
                panic!("{name} must name a build-time payload; use build-appliance.ps1")
            }))
            .canonicalize()
            .unwrap_or_else(|error| panic!("cannot resolve {name}: {error}"));
            println!("cargo:rerun-if-changed={}", path.display());
            println!("cargo:rustc-env={name}={}", path.display());
        }
    }
}
