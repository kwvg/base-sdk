# Rust toolchain, derived from rust-toolchain.toml

# rustup and dtolnay/rust-toolchain read the same file, so a bump there
# moves every consumer at once. Host target only; cross-compilation needs a
# compiler configured for it and arrives with one in cxx.nix.

{ pkgs, toolchainFile }:

let
  # rust-overlay propagates a cc wrapper, which on Linux is GCC and would
  # shadow the compiler cxx.nix chose. cargo links with the stdenv's cc.
  toolchain = (pkgs.rust-bin.fromRustupToolchainFile toolchainFile).overrideAttrs (_: {
    propagatedBuildInputs = [ ];
    depsHostHostPropagated = [ ];
    depsTargetTargetPropagated = [ ];
  });
in

{
  packages = [ toolchain ];

  env = {
    CARGO_TERM_COLOR = "always";
  };
}
