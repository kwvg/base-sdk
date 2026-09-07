# Rust toolchain pinned from rust-toolchain.toml

{ pkgs, toolchainFile }:

{
  packages = [ (pkgs.rust-bin.fromRustupToolchainFile toolchainFile) ];

  env = {
    CARGO_TERM_COLOR = "always";
  };
}
