//! Prebuilt `sp-serve` binaries embedded at build time (see `build.rs`).

/// Remote CPU architecture, from `uname -m`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    Aarch64,
}

impl Arch {
    /// Parse `uname -m` output.
    #[must_use]
    pub fn parse(uname: &str) -> Option<Self> {
        match uname.trim() {
            "x86_64" | "amd64" => Some(Self::X86_64),
            "aarch64" | "arm64" => Some(Self::Aarch64),
            _ => None,
        }
    }

    /// Short name used in the deployed file name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }

    /// Env var naming a prebuilt binary path (used by `build.rs`).
    #[must_use]
    pub fn env_var(self) -> &'static str {
        match self {
            Self::X86_64 => "SP_SERVE_X86_64",
            Self::Aarch64 => "SP_SERVE_AARCH64",
        }
    }
}

static SERVE_X86_64: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/sp-serve-x86_64"));
static SERVE_AARCH64: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/sp-serve-aarch64"));

/// The embedded `sp-serve` binary for `arch`; `None` when the build embedded
/// only a placeholder.
#[must_use]
pub fn serve_binary(arch: Arch) -> Option<&'static [u8]> {
    let bin = match arch {
        Arch::X86_64 => SERVE_X86_64,
        Arch::Aarch64 => SERVE_AARCH64,
    };
    (!bin.is_empty()).then_some(bin)
}
