# CodeQL CLI, pinned, from the archive built for this platform

# The version is the cliVersion github/codeql-action v4.37.1 links: which CLI
# answers decides what the analysis reports, since database creation and bare
# pack references resolve against it, while the lock binds only the queries.

{ pkgs, lib }:

let
  version = "2.26.1";

  # Per-platform archives, against 1.6 GiB for the universal one. The
  # digests are what the release API publishes, so a pin is checkable
  # without doing the download.
  linux64 = {
    file = "codeql-linux64.zip";
    hash = "sha256-FUgN2m4gM2qcfdy2Fx4OkVXx/nOh0xuurBU4IcuJrqs=";
  };
  osx64 = {
    file = "codeql-osx64.zip";
    hash = "sha256-YcXStT4c2O4r1XwxpVxXr1P/qv3xnEbSNBcExsrPNdM=";
  };

  # CodeQL publishes no arm64 Linux build, so that platform takes the x86_64
  # archive and emulates it. Everything else runs the archive natively.
  targets = {
    x86_64-linux = {
      asset = linux64;
      dir = "linux64";
      emulate = false;
    };
    aarch64-linux = {
      asset = linux64;
      dir = "linux64";
      emulate = true;
    };
    x86_64-darwin = {
      asset = osx64;
      dir = "osx64";
      emulate = false;
    };
    aarch64-darwin = {
      asset = osx64;
      dir = "osx64";
      emulate = false;
    };
  };

  target = targets.${pkgs.stdenv.hostPlatform.system};

  # The Linux archive names its tracer lib64trace.so and bundles an x86_64
  # JDK that will not run from a Nix store. The macOS one needs neither: its
  # library is libtrace.dylib already, and its JDK runs as shipped.
  linuxFixup = ''
    ln -sf $out/codeql/tools/linux64/lib64trace.so \
      $out/codeql/tools/linux64/libtrace.so
    rm -rf $out/codeql/tools/linux64/java
    ln -s ${pkgs.zulu17} $out/codeql/tools/linux64/java
  '';

  # Every x86_64 executable, not the two the Rust extractor needs today, so
  # a language added later is covered. Shared objects are left alone because
  # a .so replaced by a script breaks whoever dlopens it.
  #
  # This hangs off postFixup rather than the install phase below so it runs
  # after autopatchelf has had its say.
  emulateFixup = ''
    find $out/codeql -type f -perm -u+x -print0 |
      while IFS= read -r -d "" bin; do
        case "$(file -b "$bin")" in
          *ELF*executable*x86-64*)
            mv "$bin" "$bin.x86_64"
            cat > "$bin" <<WRAP
    #!${pkgs.runtimeShell}
    exec ${lib.getExe' pkgs.qemu-user "qemu-x86_64"} \
      -L ${pkgs.pkgsCross.gnu64.glibc.out} "$bin.x86_64" "\$@"
    WRAP
            chmod +x "$bin"
            ;;
        esac
      done
  '';

  codeql = pkgs.codeql.overrideAttrs (old: {
    inherit version;

    # fetchurl, not the fetchzip nixpkgs uses: this hashes the file, which is
    # the digest above, where fetchzip hashes the unpacked tree, which
    # nothing publishes.
    src = pkgs.fetchurl {
      url = "https://github.com/github/codeql-cli-binaries/releases/download/v${version}/${target.asset.file}";
      inherit (target.asset) hash;
    };

    nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [
      pkgs.unzip
      pkgs.file
    ];

    # Replaced rather than extended: nixpkgs' phase assumes the universal
    # archive and rewires linux64 paths that the macOS one does not have.
    installPhase = ''
      runHook preInstall

      mkdir -p $out/codeql $out/bin
      cp -R * $out/codeql/
      ${lib.optionalString (target.dir == "linux64") linuxFixup}
      ln -s $out/codeql/codeql $out/bin/

      runHook postInstall
    '';

    postFixup = (old.postFixup or "") + lib.optionalString target.emulate emulateFixup;
  });
in

{
  packages = [ codeql ];
}
