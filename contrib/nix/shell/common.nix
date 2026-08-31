# Everything the shells share: the mods and the assembler

# A shell is a list of mods, and which flake input each one takes is settled
# once here, so a second shell cannot be given something different from what
# the first was.

{
  pkgs,
  lib,
  inputs,
  root,
}:

let
  # Folds mods into the arguments mkShell takes. A mod contributes packages,
  # environment and at most one stdenv; two mods setting the same variable
  # throws rather than letting list order pick a winner.
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
    rust = import ../mods/rust.nix {
      inherit pkgs;
      toolchainFile = root + "/rust-toolchain.toml";
    };

    python = import ../mods/python.nix {
      inherit pkgs lib;
      inherit (inputs) uv2nix pyproject-nix pyproject-build-systems;
      workspaceRoot = root;
      # Oldest interpreter requires-python admits.
      python = pkgs.python311;
    };

    cxx = import ../mods/cxx.nix { inherit pkgs lib; };

    nixpkgs = import ../mods/nixpkgs.nix { inherit pkgs; };
  };
}
