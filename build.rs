//! Embeds the prebuilt `sp-serve` binaries for supported remote targets.
//!
//! Source resolution per target, first hit wins:
//! 1. env var `SP_SERVE_X86_64` / `SP_SERVE_AARCH64` (path to the binary);
//! 2. `<target dir>/<triple>/release/sp-serve`, where the target dir is `CARGO_TARGET_DIR` if set,
//!    else `target/` under the package root (cargo cross-built);
//! 3. empty placeholder: `sp` builds fine, but deploy fails with a clear error naming the env var
//!    to set. A `cargo:warning` is emitted so the degraded embed is visible at build time already.

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
    println!("cargo:rerun-if-env-changed=CARGO_TARGET_DIR");
    // The daemon checks the deployed binary reports this version (see
    // remote.rs); a version bump must re-embed and re-check.
    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let serve_manifest = manifest_dir
        .join("crates")
        .join("sp-serve")
        .join("Cargo.toml");
    println!("cargo:rerun-if-changed={}", serve_manifest.display());
    let serve_version = package_version(&serve_manifest);
    println!("cargo:rustc-env=SP_SERVE_VERSION={serve_version}");
    // Relative values resolve against the build script's cwd (package root),
    // the same place the default `target/` lives.
    let target_dir = env::var_os("CARGO_TARGET_DIR")
        .filter(|v| !v.is_empty())
        .map_or_else(|| PathBuf::from("target"), PathBuf::from);
    for (env_var, triple, out_name) in TARGETS {
        println!("cargo:rerun-if-env-changed={env_var}");
        // Watch the candidate path unconditionally: after a placeholder build,
        // a later cross-build dropping the binary there must re-run the embed.
        // (Emitting any rerun directive disables cargo's default
        // rebuild-on-any-change, so this must not depend on `src` being Some.)
        let candidate = target_dir.join(triple).join("release").join("sp-serve");
        println!("cargo:rerun-if-changed={}", candidate.display());
        let src = env::var_os(env_var)
            .map(PathBuf::from)
            .filter(|p| p.is_file())
            .or_else(|| candidate.is_file().then(|| candidate.clone()));
        let dest = out_dir.join(out_name);
        if let Some(p) = src {
            println!("cargo:rerun-if-changed={}", p.display());
            std::fs::copy(&p, &dest).expect("copy sp-serve binary");
        } else {
            println!(
                "cargo:warning={env_var} is not set and {} was not found; embedding an empty \
                 placeholder. Remote deploy will fail until you cross-build sp-serve there or \
                 point {env_var} at the binary",
                candidate.display()
            );
            std::fs::write(&dest, []).expect("write empty placeholder");
        }
    }
}

/// `package.version` of the sp-serve manifest. A line scan avoids a build-time
/// toml dependency; the manifest is small, hand-written and package-owned.
fn package_version(path: &std::path::Path) -> String {
    let text =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let mut in_package = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_package = line == "[package]";
        } else if in_package
            && let Some((key, value)) = line.split_once('=')
            && key.trim() == "version"
            && let Some(v) = value
                .trim()
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
            && !v.is_empty()
        {
            return v.to_owned();
        }
    }
    panic!("no [package] version in {}", path.display());
}
