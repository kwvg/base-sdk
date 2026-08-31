# The Xcode-extracted macOS SDK, and the only place its URL and hash live

# nixpkgs' apple-sdk is darwin-only and its pkgsCross darwin sets want
# cctools, unavailable on Linux. This is the SDK Bitcoin Core and Dash Core
# cross-build against: LLVM supplies the binutils, Apple the headers.

{ pkgs }:

let
  # Xcode release and build id, as the tarball names them.
  version = "26.1.1-17B100";
in

pkgs.stdenvNoCC.mkDerivation {
  pname = "xcode-sdk";
  inherit version;

  src = pkgs.fetchurl {
    url = "https://bitcoincore.org/depends-sources/sdks/Xcode-${version}-extracted-SDK-with-libcxx-headers.tar";
    hash = "sha256-lgD6k2RN9nTukWteLIprqNrPYxmWpl3JItADuYteo7E=";
  };

  dontConfigure = true;
  dontBuild = true;

  # A plain tar of one tree, so the archive root becomes $out and a consumer
  # passes $out straight to -isysroot.
  installPhase = ''
    runHook preInstall
    mkdir -p $out
    cp -a ./* $out/
    runHook postInstall
  '';

  # Mach-O stubs and headers; none of it is for the build platform.
  dontFixup = true;

  passthru = {
    # Both reach clang as flags: what the SDK is, and the oldest macOS the
    # artifacts should run on.
    sdkVersion = "14.0";
    minVersion = "14.0";
    # lld is not ld64, and clang gates features on the linker version.
    linkerVersion = "711";
  };
}
