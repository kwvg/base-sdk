# Bazel from nixpkgs, with buildifier; the flake lock pins the version

{ pkgs }:

{
  packages = [
    pkgs.bazel_9
    pkgs.buildifier
  ];
}
