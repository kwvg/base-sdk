# Common logic shared between development shells

{
  pkgs,
  lib,
  inputs,
  root,
}:

let
  # Folds modules into mkShell arguments. Conflicting variables will throw
  # instead of allowing order-sensitive assignment.
  compose =
    mods:
    let
      envs = map (m: m.env or { }) mods;
      names = lib.concatMap lib.attrNames envs;
      clashes = lib.unique (lib.filter (n: lib.count (m: m == n) names > 1) names);
    in
    if clashes != [ ] then
      throw "variables redefined: ${lib.concatStringsSep ", " clashes}"
    else
      pkgs.mkShell (
        { packages = lib.concatMap (m: m.packages or [ ]) mods; } // lib.foldl' (a: b: a // b) { } envs
      );
in
{
  inherit
    pkgs
    lib
    compose
    ;

  mods = {
    nixpkgs = import ../mods/nixpkgs.nix { inherit pkgs; };
    python = import ../mods/python.nix {
      inherit pkgs lib;
      inherit (inputs) uv2nix pyproject-nix pyproject-build-systems;
      workspaceRoot = root;
      # Must match `project.requires-python` in pyproject.toml, effective floor.
      python = pkgs.python311;
    };
    rust = import ../mods/rust.nix {
      inherit pkgs;
      toolchainFile = root + "/rust-toolchain.toml";
    };
  };
}
