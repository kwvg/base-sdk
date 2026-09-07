# LLVM C(++) compiler setup and configuration

{ pkgs, lib }:

let
  llvm = pkgs.llvmPackages_20;

  # clang -print-resource-dir names the main output, but the builtin headers are
  # split into .lib, so the flag has to be passed explicitly.
  resourceDir = "${llvm.clang-unwrapped.lib}/lib/clang/20";

  # --ld-path names lld directly, where -fuse-ld=lld would find the nixpkgs
  # bintools wrapper on PATH. Mach-O needs ld64.
  ldFor = flavour: "--ld-path=${llvm.lld}/bin/${flavour}";

  # Per-target definitions keyed against `hostTriple`
  defs = {
    "aarch64-unknown-linux-gnu" = {
      clangTarget = "aarch64-unknown-linux-gnu";
      kind = "glibc";
      cross = pkgs.pkgsCross.aarch64-multiplatform;
    };
    "x86_64-unknown-linux-gnu" = {
      clangTarget = "x86_64-unknown-linux-gnu";
      kind = "glibc";
      cross = pkgs.pkgsCross.gnu64;
    };
  };

  # glibc splits its outputs, so there isn't a unified tree to hand --sysroot
  # headers are in .dev, crt objects and libraries are in .out. libgcc_s.so
  # is a third output independent of the compiler's libraries.
  glibcFlags =
    d:
    let
      gccLib = "${d.cross.stdenv.cc.cc}/lib/gcc/${d.clangTarget}/${d.cross.stdenv.cc.cc.version}";
    in
    [
      "-isystem ${d.cross.stdenv.cc.libc.dev}/include"
      "-B${d.cross.stdenv.cc.libc.out}/lib"
      "-B${gccLib}"
      "-L${d.cross.stdenv.cc.libc.out}/lib"
      "-L${gccLib}"
      "-L${d.cross.stdenv.cc.cc.libgcc}/lib"
      (ldFor "ld.lld")
    ];

  # libstdc++ comes from the cross GCC rather than from the sysroot
  libStdCxx =
    d:
    let
      cc = d.cross.stdenv.cc.cc;
      inc = "${cc}/include/c++/${cc.version}";
    in
    [
      "-isystem ${inc}"
      "-isystem ${inc}/${d.clangTarget}"
      "-L${cc}/${d.clangTarget}/lib"
    ];

  cxxExtra = d: { glibc = libStdCxx; }.${d.kind} d;
  flagsFor = d: { glibc = glibcFlags; }.${d.kind} d;

  # A driver per target and language. C_INCLUDE_PATH and CPLUS_INCLUDE_PATH
  # are unset because the host's include paths would otherwise leak into a
  # cross compile.
  driver =
    name: bin: d: extra:
    pkgs.writeShellScriptBin name ''
      exec env -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH \
        ${llvm.clang-unwrapped}/bin/${bin} \
        --target=${d.clangTarget} \
        -resource-dir=${resourceDir} \
        ${lib.concatStringsSep " \\\n        " (extra ++ flagsFor d)} \
        "$@"
    '';

  # `cc-rs` and `cargo` spell the same target differently.
  ccKey = t: builtins.replaceStrings [ "-" ] [ "_" ] t;
  cargoKey = t: lib.toUpper (ccKey t);

  wire =
    t:
    let
      d = defs.${t} or (throw "cxx.nix knows no C toolchain for ${t}");
      cc = driver "${t}-cc" "clang" d [ ];
      cxx = driver "${t}-c++" "clang++" d (cxxExtra d);
    in
    {
      packages = [
        cc
        cxx
      ];
      env = {
        "CC_${ccKey t}" = "${cc}/bin/${t}-cc";
        "CXX_${ccKey t}" = "${cxx}/bin/${t}-c++";
        "AR_${ccKey t}" = "${llvm.bintools-unwrapped}/bin/llvm-ar";
        "CARGO_TARGET_${cargoKey t}_LINKER" = "${cc}/bin/${t}-cc";
      };
    };
in
{
  # Adding clang to packages would not displace the cc-wrapper the default
  # stdenv puts on PATH, so the shell is built against this stdenv instead.
  compiler = {
    stdenv = llvm.stdenv;
    packages = [ llvm.bintools ];
  };

  # attrNames does not force the values, so listing targets is cheap even
  # though each entry reaches for a pkgsCross set.
  knownTargets = builtins.attrNames defs;

  forTargets =
    targets:
    let
      wired = map wire targets;
    in
    {
      packages = lib.concatMap (w: w.packages) wired;
      env = lib.foldl' (a: w: a // w.env) { } wired;
    };
}
