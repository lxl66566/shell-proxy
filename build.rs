//! Embeds the prebuilt `sp-serve` binaries for supported remote targets.
//!
//! Source resolution per target, first hit wins:
//! 1. env var `SP_SERVE_X86_64` / `SP_SERVE_AARCH64` (path to the binary);
//! 2. `target/<triple>/release/sp-serve` in the workspace (cargo cross-built);
//! 3. empty placeholder: `sp` builds fine, but deploy fails with a clear error naming the env var
//!    to set.

use std::{env, path::PathBuf};

const TARGETS: [(&str, &str, &str); 2] = [
    (
        "SP_SERVE_X86_64",
        "x86_64-unknown-linux-musl",
        "sp-serve-x86_64",
    ),
    (
        "SP_SERVE_AARCH64",
        "aarch64-unknown-linux-musl",
        "sp-serve-aarch64",
    ),
];

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    for (env_var, triple, out_name) in TARGETS {
        println!("cargo:rerun-if-env-changed={env_var}");
        // Watch the candidate path unconditionally: after a placeholder build,
        // a later cross-build dropping the binary there must re-run the embed.
        // (Emitting any rerun directive disables cargo's default
        // rebuild-on-any-change, so this must not depend on `src` being Some.)
        let candidate = PathBuf::from(format!("target/{triple}/release/sp-serve"));
        println!("cargo:rerun-if-changed={}", candidate.display());
        let src = env::var_os(env_var)
            .map(PathBuf::from)
            .filter(|p| p.is_file())
            .or_else(|| candidate.is_file().then_some(candidate));
        let dest = out_dir.join(out_name);
        match src {
            Some(p) => {
                println!("cargo:rerun-if-changed={}", p.display());
                std::fs::copy(&p, &dest).expect("copy sp-serve binary");
            },
            None => std::fs::write(&dest, []).expect("write empty placeholder"),
        }
    }
}
