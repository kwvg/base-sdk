# Everything both shells share: the mods, the target policy, the assembler

# ci and dev need the same ingredients built the same way, so which flake
# input a mod takes is settled once here, and dev cannot drift from what ci
# was given.

{
  pkgs,
  lib,
  inputs,
  root,
}:

let
  cxx = import ../mods/cxx.nix {
    inherit pkgs lib;
    xcodeSdk = import ../mods/xcode_sdk.nix { inherit pkgs; };
  };

  # Targets that are not a platform anyone here runs, so no host is ever
  # excluded from them.
  constants = [ "wasm32-unknown-unknown" ];

  # The C driver table minus the host's own, which the stdenv already
  # compiles for. Windows stays in because no host is Windows.
  #
  # rustcTarget, not hostPlatform.config: the table is keyed by Rust triples,
  # and the two disagree on aarch64-darwin, where config is arm64-apple-darwin.
  hostTriple = pkgs.stdenv.hostPlatform.rust.rustcTarget;
  crossTargets = lib.filter (t: t != hostTriple) cxx.knownTargets;

  nightlyWith =
    extra:
    (pkgs.rust-bin.fromRustupToolchainFile (root + "/rust-toolchain.toml")).override {
      targets = constants ++ extra;
    };

  # Folds mods into the arguments mkShell takes. A mod contributes packages,
  # environment, a shell hook and at most one stdenv; two mods setting the
  # same variable throws rather than letting list order pick a winner.
  compose =
    mods:
    let
      envs = map (m: m.env or { }) mods;
      names = lib.concatMap lib.attrNames envs;
      clashes = lib.unique (lib.subtractLists (lib.unique names) names);

      stdenvs = lib.filter (s: s != null) (map (m: m.stdenv or null) mods);
      mkShell =
        if stdenvs == [ ] then
          pkgs.mkShell
        else if lib.length stdenvs == 1 then
          pkgs.mkShell.override { stdenv = lib.head stdenvs; }
        else
          throw "more than one mod chose a stdenv";
    in
    if clashes != [ ] then
      throw "mods set the same variable twice: ${lib.concatStringsSep ", " clashes}"
    else
      mkShell (
        {
          packages = lib.concatMap (m: m.packages or [ ]) mods;
          shellHook = lib.concatStringsSep "\n" (lib.filter (h: h != "") (map (m: m.shellHook or "") mods));
        }
        // lib.foldl' (a: b: a // b) { } envs
      );
in

{
  inherit
    pkgs
    lib
    cxx
    crossTargets
    nightlyWith
    compose
    ;

  mods = {
    # Both channels in one shell: nightly as rust-toolchain.toml names it,
    # and the floor Cargo.toml declares, which lint_cargo.py holds equal.
    # stable is a moving target, so it stays on dtolnay outside this shell.
    rust = import ../mods/rust.nix {
      inherit pkgs lib;
      default = "nightly";
      toolchains = {
        nightly = nightlyWith [ ];
        # minimal: the MSRV job builds and tests and nothing lints against
        # it, so the .default profile's docs are dead weight.
        msrv = pkgs.rust-bin.stable."1.85.0".minimal;
      };
    };

    python = import ../mods/python.nix {
      inherit pkgs lib;
      inherit (inputs) uv2nix pyproject-nix pyproject-build-systems;
      workspaceRoot = root;
      # Oldest interpreter requires-python admits.
      python = pkgs.python311;
    };

    codeql = import ../mods/codeql.nix { inherit pkgs lib; };

    # The compiler alone. Cross drivers are `cxx.forTargets`, which only
    # dev.nix calls, so no shell picks up a target by being on this list.
    cxx = cxx.compiler;

    nixpkgs = import ../mods/nixpkgs.nix { inherit pkgs; };
  };
}
