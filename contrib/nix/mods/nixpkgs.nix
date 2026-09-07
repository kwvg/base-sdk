# Native packages sourced from the Nix Packages collection (nixpkgs)

{ pkgs }:

{
  packages = [
    pkgs.git
    pkgs.nixfmt
    pkgs.nodejs_24

    # Packages synced with '.tools' from 'pyproject.toml'.
    pkgs.ruff
    pkgs.semgrep
    pkgs.taplo
    pkgs.zensical
  ];
}
