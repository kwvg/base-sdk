# The Xcode-extracted macOS SDK, and the only place its URL and hash live

# nixpkgs' apple-sdk has no libc++ headers, so host and cross compiles would
# disagree about `<string>`. This is the SDK Bitcoin Core cross-builds against.

{ pkgs }:

let
  # Xcode release and build id, as named by the tarball.
  version = "26.1.1-17B100";

  # The macOS version of the extract, not the deployment target below.
  sdkVersion = "26.1";

  platform = "Platforms/MacOSX.platform";
  sdkDir = "${platform}/Developer/SDKs";
in

pkgs.stdenvNoCC.mkDerivation (finalAttrs: {
  pname = "xcode-sdk";
  inherit version;

  src = pkgs.fetchurl {
    url = "https://bitcoincore.org/depends-sources/sdks/Xcode-${version}-extracted-SDK-with-libcxx-headers.tar";
    hash = "sha256-lgD6k2RN9nTukWteLIprqNrPYxmWpl3JItADuYteo7E=";
  };

  dontConfigure = true;
  dontBuild = true;

  # The archive is a bare sysroot, so the tree a DEVELOPER_DIR needs is built
  # around it. xcbuild's `xcrun` reads the plists below, which the archive
  # does not carry.
  installPhase = ''
    runHook preInstall

    mkdir -p "$out/${sdkDir}/MacOSX.sdk" "$out/Toolchains/XcodeDefault.xctoolchain"
    cp -a ./* "$out/${sdkDir}/MacOSX.sdk/"

    cat > "$out/${platform}/Info.plist" <<'EOF'
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0"><dict>
      <key>CFBundleIdentifier</key><string>com.apple.platform.macosx</string>
      <key>Identifier</key><string>com.apple.platform.macosx</string>
      <key>Name</key><string>macosx</string>
      <key>FamilyIdentifier</key><string>macosx</string>
      <key>FamilyName</key><string>macOS</string>
      <key>Description</key><string>macOS</string>
      <key>Type</key><string>Platform</string>
    </dict></plist>
    EOF

    cat > "$out/${sdkDir}/MacOSX.sdk/SDKSettings.plist" <<'EOF'
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0"><dict>
      <key>CanonicalName</key><string>macosx@SDK_VERSION@</string>
      <key>DisplayName</key><string>macOS @SDK_VERSION@</string>
      <key>MinimalDisplayName</key><string>@SDK_VERSION@</string>
      <key>Version</key><string>@SDK_VERSION@</string>
      <key>IsBaseSDK</key><string>YES</string>
    </dict></plist>
    EOF

    cat > "$out/Toolchains/XcodeDefault.xctoolchain/ToolchainInfo.plist" <<'EOF'
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0"><dict>
      <key>Identifier</key><string>com.apple.dt.toolchain.XcodeDefault</string>
    </dict></plist>
    EOF

    sed -i "s/@SDK_VERSION@/${sdkVersion}/g" "$out/${sdkDir}/MacOSX.sdk/SDKSettings.plist"

    # Apple's xcrun validates a DEVELOPER_DIR by looking for this.
    ${pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isDarwin ''
      mkdir -p "$out/usr/bin"
      ln -s ${pkgs.lib.getExe' pkgs.xcbuild "xcrun"} "$out/usr/bin/xcrun"
    ''}

    # Names a caller may ask for by canonical name.
    ln -s MacOSX.sdk "$out/${sdkDir}/MacOSX${sdkVersion}.sdk"
    ln -s MacOSX.sdk "$out/${sdkDir}/MacOSX${builtins.head (pkgs.lib.splitString "." sdkVersion)}.sdk"

    runHook postInstall
  '';

  # Mach-O stubs and headers for the target, so nothing to fix up.
  dontFixup = true;

  passthru = {
    # `$out` is a DEVELOPER_DIR, so the sysroot is named separately.
    sysroot = "${finalAttrs.finalPackage}/${sdkDir}/MacOSX.sdk";
    inherit sdkVersion;
    # The oldest macOS the artifacts should run on.
    minVersion = "14.0";
    # lld is not ld64, and clang gates features on the linker version.
    linkerVersion = "711";
  };
})
