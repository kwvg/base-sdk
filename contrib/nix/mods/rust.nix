# Rust toolchains, default included in PATH, remaining as TOOLCHAIN_*

{
  default,
  lib,
  pkgs,
  toolchains,
}:

let
  # Purge C compiler wrapper propagated by rust-overlay to prioritize
  # stdenv's C compiler (defined in cxx.nix)
  bare = lib.mapAttrs (
    _: t:
    t.overrideAttrs (_: {
      propagatedBuildInputs = [ ];
      depsHostHostPropagated = [ ];
      depsTargetTargetPropagated = [ ];
    })
  ) toolchains;

  # A path per non-default toolchain, since only one can own `cargo` at a time.
  named = lib.mapAttrs' (name: t: lib.nameValuePair "TOOLCHAIN_${lib.toUpper name}" "${t}") (
    lib.filterAttrs (name: _: name != default) bare
  );
in
{
  packages = [ bare.${default} ];

  env = {
    CARGO_TERM_COLOR = "always";
  }
  // named;
}
