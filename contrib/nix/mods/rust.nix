# Rust toolchain pinned from rust-toolchain.toml

{
  pkgs,
  toolchainFile,
  targets,
}:

let
  # Purge C compiler wrapper propagated by rust-overlay to prioritize
  # stdenv's C compiler (defined in cxx.nix)
  toolchain =
    ((pkgs.rust-bin.fromRustupToolchainFile toolchainFile).override { inherit targets; }).overrideAttrs
      (_: {
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
