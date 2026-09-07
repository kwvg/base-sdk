# LLVM C(++) compiler setup and configuration

{ pkgs, lib }:

let
  llvm = pkgs.llvmPackages_20;
in
{
  packages = [ llvm.bintools ];
  stdenv = llvm.stdenv;
}
