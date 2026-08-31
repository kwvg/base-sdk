# Rust toolchains, built by Nix and put on PATH

# No rustup. It is a version manager, and a pinned shell has already chosen the
# version; having it would mean writing toolchain links into the caller's
# ~/.rustup, which is host state that entering a shell should not touch.

{
  pkgs,
  lib,
  # Attribute set of name to toolchain derivation.
  toolchains,
  # Which of them a bare `cargo` resolves to.
  default,
}:

let
  # rust-overlay propagates a cc wrapper, GCC on Linux, which would shadow
  # the compiler cxx.nix chose.
  bare = lib.mapAttrs (
    _: t:
    t.overrideAttrs (_: {
      propagatedBuildInputs = [ ];
      depsHostHostPropagated = [ ];
      depsTargetTargetPropagated = [ ];
    })
  ) toolchains;

  # A path per toolchain that is not the default, since only one of them can
  # own the name `cargo`. This is what `cargo +name` was for.
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
