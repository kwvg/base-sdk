# Rust toolchain, derived from rust-toolchain.toml

# rustup and dtolnay/rust-toolchain read the same file, so a bump there
# moves every consumer at once. Host target only; cross-compilation needs a
# compiler configured for it and arrives with one in cxx.nix.

{ pkgs, toolchainFile }:

{
  packages = [ (pkgs.rust-bin.fromRustupToolchainFile toolchainFile) ];

  env = {
    CARGO_TERM_COLOR = "always";
  };
}
