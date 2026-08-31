# Clang 20 as the C and C++ compiler

# nixpkgs' stdenv is GCC on Linux and Clang on Darwin, so a build would use a
# different compiler per host, and which one it was would depend on where the
# build ran rather than on anything this repository says.

{ pkgs, lib }:

let
  llvm = pkgs.llvmPackages_20;
in

{
  # Adding clang to packages would not displace the cc-wrapper the default
  # stdenv puts on PATH, so the shell is built against this one instead.
  stdenv = llvm.stdenv;

  packages = [ llvm.bintools ];
}
