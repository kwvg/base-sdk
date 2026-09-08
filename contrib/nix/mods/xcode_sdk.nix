# Xcode-derived macOS SDK with libcxx headers

{ pkgs }:

let
  # Xcode release and build ID
  version = "26.1.1-17B100";
in

pkgs.stdenvNoCC.mkDerivation {
  inherit version;

  # Archive contains stubs and headers, nothing to configure, build or fix
  dontBuild = true;
  dontConfigure = true;
  dontFixup = true;

  pname = "xcode-sdk";
  src = pkgs.fetchurl {
    url = "https://bitcoincore.org/depends-sources/sdks/Xcode-${version}-extracted-SDK-with-libcxx-headers.tar";
    hash = "sha256-lgD6k2RN9nTukWteLIprqNrPYxmWpl3JItADuYteo7E=";
  };

  installPhase = ''
    runHook preInstall
    mkdir -p $out
    cp -a ./* $out/
    runHook postInstall
  '';

  passthru = {
    # Target macOS version binaries are expected to support.
    minVersion = "14.0";
    # ld64 version clang is told to assume, as lld reports its own.
    linkerVersion = "711";
  };

  meta = {
    description = "macOS SDK extracted from Xcode, with libc++ headers";
    license = pkgs.lib.licenses.unfree;
  };
}
