# Common logic shared between development shells

{
  pkgs,
  lib,
  inputs,
  root,
}:

let
  # Target platform for web demos bundled with documentation.
  commonTargets = [ "wasm32-unknown-unknown" ];

  rsComponents = (lib.importTOML (root + "/rust-toolchain.toml")).toolchain.components;

  # Folds modules into mkShell arguments. Conflicting variables or stdenvs
  # will throw instead of allowing order-sensitive assignment.
  compose =
    mods:
    let
      named = m: m._name or "<unnamed>";
      envs = map (m: m.env or { }) mods;
      names = lib.concatMap lib.attrNames envs;
      clashes = lib.unique (lib.filter (n: lib.count (m: m == n) names > 1) names);
      chosen = lib.filter (m: (m.stdenv or null) != null) mods;
      mkShell =
        if chosen == [ ] then
          pkgs.mkShell
        else if lib.length chosen == 1 then
          pkgs.mkShell.override { stdenv = (lib.head chosen).stdenv; }
        else
          throw "stdenv redefined: ${lib.concatMapStringsSep ", " named chosen}";
    in
    if clashes != [ ] then
      throw "variables redefined: ${lib.concatStringsSep ", " clashes}"
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
    compose
    ;

  mods = lib.mapAttrs (name: m: m // { _name = name; }) {
    codeql = import ../mods/codeql.nix { inherit pkgs lib; };
    cxx = import ../mods/cxx.nix { inherit pkgs lib; };
    nixpkgs = import ../mods/nixpkgs.nix { inherit pkgs; };
    python = import ../mods/python.nix {
      inherit pkgs lib;
      inherit (inputs) uv2nix pyproject-nix pyproject-build-systems;
      workspaceRoot = root;
      # Must match `project.requires-python` in pyproject.toml, effective floor.
      python = pkgs.python311;
    };
    rust = import ../mods/rust.nix {
      inherit pkgs lib;
      default = "nightly";
      toolchains = {
        nightly = (pkgs.rust-bin.fromRustupToolchainFile (root + "/rust-toolchain.toml")).override {
          targets = commonTargets;
        };
        # Must match `workspace.package.rust-version` in root Cargo.toml.
        msrv = pkgs.rust-bin.stable."1.85.0".minimal.override { extensions = rsComponents; };
      };
    };
  };
}
