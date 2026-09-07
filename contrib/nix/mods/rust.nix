# Rust toolchain pinned from rust-toolchain.toml

{
  pkgs,
  toolchainFile,
  targets,
}:

{
  packages = [
    ((pkgs.rust-bin.fromRustupToolchainFile toolchainFile).override { inherit targets; })
  ];

  env = {
    CARGO_TERM_COLOR = "always";
  };
}
