# Python tools, built from uv.lock by uv2nix

# nixpkgs has no pymarkdownlnt, its four dependencies, or pygments-styles, and
# a pip shell hook would need the network on every cold shell. So uv.lock
# records what pyproject.toml's floors resolved to, and uv2nix derives it.

{
  pkgs,
  lib,
  uv2nix,
  pyproject-nix,
  pyproject-build-systems,
  workspaceRoot,
  python,
}:

let
  workspace = uv2nix.lib.workspace.loadWorkspace { inherit workspaceRoot; };

  # A wheel needs no build backend; prefer one where the lock offers both.
  overlay = workspace.mkPyprojectOverlay { sourcePreference = "wheel"; };

  # rjsmin has no wheel for every platform and its sdist names no backend.
  overrides = final: prev: {
    rjsmin = prev.rjsmin.overrideAttrs (old: {
      nativeBuildInputs =
        (old.nativeBuildInputs or [ ]) ++ final.resolveBuildSystem { setuptools = [ ]; };
    });
  };

  pythonSet = (pkgs.callPackage pyproject-nix.build.packages { inherit python; }).overrideScope (
    lib.composeManyExtensions [
      pyproject-build-systems.overlays.default
      overlay
      overrides
    ]
  );

  # Only the `lib` extra. `tools` is the programs the checks execute, which
  # nixpkgs carries and lint.nix takes from there, so resolving them here
  # would build a second copy and drag semgrep's dependency tree along.
  venv = pythonSet.mkVirtualEnv "dash-base-sdk-lib" { dash-base-sdk = [ "lib" ]; };
in

{
  packages = [
    venv

    # How uv.lock is regenerated; nothing at run time needs it.
    pkgs.uv
  ];

  env = {
    UV_PYTHON = "${venv}/bin/python";
    UV_NO_SYNC = "1";
  };
}
