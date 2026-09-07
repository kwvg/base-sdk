# Rust toolchains, default included in PATH, remaining as TOOLCHAIN_*

{
  default,
  lib,
  toolchains,
}:

let
  # A path per non-default toolchain, since only one can own `cargo` at a time.
  named = lib.mapAttrs' (name: t: lib.nameValuePair "TOOLCHAIN_${lib.toUpper name}" "${t}") (
    lib.filterAttrs (name: _: name != default) toolchains
  );
in
{
  packages = [ toolchains.${default} ];

  env = {
    CARGO_TERM_COLOR = "always";
  }
  // named;
}
