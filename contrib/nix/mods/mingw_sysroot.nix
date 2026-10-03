# A MinGW-w64 sysroot with winpthreads, laid out the way clang's MinGW driver
# looks for a GCC installation

{ pkgs }:

let
  cross = pkgs.pkgsCross.mingwW64;
  triple = "x86_64-w64-mingw32";
  gcc = cross.stdenv.cc.cc;
  win = cross.windows;
in

pkgs.runCommand "mingw-sysroot-${win.mingw_w64.version}" { } ''
  inc=$out/${triple}/include
  lib=$out/${triple}/lib
  gccdir=$out/lib/gcc/${triple}/${gcc.version}

  mkdir -p "$inc" "$lib" "$gccdir" "$out/include/c++"

  # Headers, with winpthreads' and mcfgthread's beside them. Linked rather
  # than copied, as the headers alone are 80 MB.
  cp -rs ${win.mingw_w64_headers}/include/. "$inc/"
  chmod -R u+w "$inc"
  cp -rs --update=none ${win.pthreads}/include/. "$inc/"
  cp -rs --update=none ${win.mcfgthreads.dev}/include/. "$inc/"

  cp -rs ${win.mingw_w64}/lib/. "$lib/"
  chmod -R u+w "$lib"
  cp -rs --update=none ${win.pthreads}/lib/. "$lib/"
  cp -rs --update=none ${win.mcfgthreads}/lib/. "$lib/"
  cp -rs --update=none ${gcc}/${triple}/lib/. "$lib/"

  cp -rs ${gcc}/lib/gcc/${triple}/${gcc.version}/. "$gccdir/"
  cp -rs ${gcc}/include/c++/${gcc.version} "$out/include/c++/"
''
