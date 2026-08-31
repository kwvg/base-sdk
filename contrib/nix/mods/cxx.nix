# Clang 20 as the C and C++ compiler, and a driver per cross target

# nixpkgs' stdenv is GCC on Linux and Clang on Darwin, so a build would use a
# different compiler per host. Cross uses the unwrapped compiler: the wrapper
# is not multi-target, and its resource dir lacks the builtin headers.

{
  pkgs,
  lib,
  # The Xcode SDK, or null for a shell that cannot reach Darwin targets.
  xcodeSdk ? null,
}:

let
  llvm = pkgs.llvmPackages_20;

  # clang -print-resource-dir names the main output, but the builtin headers
  # are split into .lib, so the flag has to be passed explicitly.
  resourceDir = "${llvm.clang-unwrapped.lib}/lib/clang/20";

  # --ld-path names lld directly, where -fuse-ld=lld would find the nixpkgs
  # bintools wrapper on PATH; that wrapper injects the host's NIX_LDFLAGS,
  # which from Darwin means Mach-O flags in an ELF link. Mach-O needs ld64.
  ldFor = flavour: "--ld-path=${llvm.lld}/bin/${flavour}";

  # What each target needs beyond --target. `clangTarget` differs from the
  # Rust triple often enough to be spelled out rather than derived.
  defs = {
    "x86_64-pc-windows-gnu" = {
      clangTarget = "x86_64-w64-mingw32";
      kind = "mingw";
      cross = pkgs.pkgsCross.mingwW64;
    };
    "x86_64-unknown-linux-gnu" = {
      clangTarget = "x86_64-unknown-linux-gnu";
      kind = "glibc";
      cross = pkgs.pkgsCross.gnu64;
    };
    "aarch64-unknown-linux-gnu" = {
      clangTarget = "aarch64-unknown-linux-gnu";
      kind = "glibc";
      cross = pkgs.pkgsCross.aarch64-multiplatform;
    };
    "x86_64-apple-darwin" = {
      clangTarget = "x86_64-apple-darwin";
      kind = "darwin";
    };
    "aarch64-apple-darwin" = {
      # Apple spells the arm64 triple differently from Rust.
      clangTarget = "arm64-apple-darwin";
      kind = "darwin";
    };
  };

  # MinGW keeps its headers and import libs apart, and libgcc comes from the
  # cross GCC's libraries without its driver ever being invoked. -B as well as
  # -L: clang emits crt2.o as a bare name, and only -B resolves that.
  mingwFlags =
    d:
    let
      gccLib = "${d.cross.stdenv.cc.cc}/lib/gcc/x86_64-w64-mingw32/${d.cross.stdenv.cc.cc.version}";
    in
    [
      "-isystem ${d.cross.windows.mingw_w64_headers}/include"
      "-B${d.cross.windows.mingw_w64}/lib"
      "-B${gccLib}"
      "-L${d.cross.windows.mingw_w64}/lib"
      "-L${gccLib}"
      # rustc's windows-gnu spec links -l:libpthread.a by that literal name,
      # and rust-std ships no self-contained copy of it.
      "-L${d.cross.windows.pthreads}/lib"
      (ldFor "ld.lld")
    ];

  # glibc splits its outputs, so there is no one tree to hand --sysroot:
  # headers are in .dev, and the crt objects and libraries in .out. libgcc_s.so
  # is a third output again, apart from the compiler's own libraries.
  glibcFlags =
    d:
    let
      gccLib = "${d.cross.stdenv.cc.cc}/lib/gcc/${d.clangTarget}/${d.cross.stdenv.cc.cc.version}";
    in
    [
      "-isystem ${d.cross.stdenv.cc.libc.dev}/include"
      # crtbeginS.o and crt1.o arrive as bare names, which -B resolves and -L
      # does not; the linker treats an explicit filename as a literal path.
      "-B${d.cross.stdenv.cc.libc.out}/lib"
      "-B${gccLib}"
      "-L${d.cross.stdenv.cc.libc.out}/lib"
      "-L${gccLib}"
      "-L${d.cross.stdenv.cc.cc.libgcc}/lib"
      (ldFor "ld.lld")
    ];

  # Lifted from Dash Core's depends/hosts/darwin.mk, which is the recipe that
  # is known to work. -nostdlibinc with explicit -iwithsysroot rather than
  # letting clang guess, and a linker version because lld is not ld64.
  darwinFlags =
    _:
    [
      "-isysroot ${xcodeSdk}"
      "-nostdlibinc"
      "-iwithsysroot/usr/include"
      "-iframeworkwithsysroot/System/Library/Frameworks"
      "-mmacos-version-min=${xcodeSdk.minVersion}"
    ]
    ++ lib.optionals (!pkgs.stdenv.hostPlatform.isDarwin) [
      "-mlinker-version=${xcodeSdk.linkerVersion}"
      (ldFor "ld64.lld")
      "-Wl,-no_adhoc_codesign"
    ];

  flagsFor =
    d:
    {
      mingw = mingwFlags;
      glibc = glibcFlags;
      darwin = darwinFlags;
    }
    .${d.kind}
      d;

  # rustc shells out to <target>-dlltool for the raw-dylib imports windows-sys
  # declares, and looks for that exact name, not llvm-dlltool. Every binary in
  # this package is target-prefixed, so none of it shadows a host tool.
  extraPkgs = d: lib.optionals (d.kind == "mingw") [ d.cross.stdenv.cc.bintools.bintools ];

  # C++ needs the libc++ headers named too, and only on Darwin are they
  # somewhere clang will not find on its own.
  cxxExtra = d: lib.optionals (d.kind == "darwin") [ "-iwithsysroot/usr/include/c++/v1" ];

  # A driver per target and language. C_INCLUDE_PATH and CPLUS_INCLUDE_PATH
  # are unset because the host's own include paths otherwise leak into a
  # cross compile, which Dash Core hit and fixed the same way.
  driver =
    name: d: extra:
    pkgs.writeShellScriptBin name ''
      exec env -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH \
        ${llvm.clang-unwrapped}/bin/clang \
        --target=${d.clangTarget} \
        -resource-dir=${resourceDir} \
        ${lib.concatStringsSep " \\\n        " (flagsFor d ++ extra)} \
        "$@"
    '';

  # cc-rs and cargo spell the same target differently.
  ccKey = t: builtins.replaceStrings [ "-" ] [ "_" ] t;
  cargoKey = t: lib.toUpper (ccKey t);

  wire =
    t:
    let
      d = defs.${t} or (throw "cxx.nix knows no C toolchain for ${t}");
      cc = driver "${t}-cc" d [ ];
      cxx = driver "${t}-c++" d (cxxExtra d);
    in
    {
      packages = [
        cc
        cxx
      ]
      ++ extraPkgs d;
      env = {
        "CC_${ccKey t}" = "${cc}/bin/${t}-cc";
        "CXX_${ccKey t}" = "${cxx}/bin/${t}-c++";
        "AR_${ccKey t}" = "${llvm.bintools-unwrapped}/bin/llvm-ar";
        "CARGO_TARGET_${cargoKey t}_LINKER" = "${cc}/bin/${t}-cc";
      };
    };

in

{
  # The compiler on its own, which is every shell's business. Adding clang to
  # packages would not displace the cc-wrapper the default stdenv puts on
  # PATH, so the shell is built against this one instead.
  compiler = {
    stdenv = llvm.stdenv;
    packages = [ llvm.bintools ];
  };

  # The enumeration lives here, so adding a target is one table entry and
  # dev.nix follows. attrNames does not force the values, so listing is cheap
  # even though each entry reaches for a pkgsCross set.
  knownTargets = builtins.attrNames defs;

  # Drivers and their variables, and nothing else: whatever shell adds these
  # already has the compiler above, so handing back a stdenv here would be a
  # second answer to a question `compose` allows only one of.
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
