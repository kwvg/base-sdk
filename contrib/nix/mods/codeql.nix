# CodeQL CLI

{ pkgs, lib }:

let
  version = "2.26.1";
  linux64 = {
    file = "codeql-linux64.zip";
    hash = "sha256-FUgN2m4gM2qcfdy2Fx4OkVXx/nOh0xuurBU4IcuJrqs=";
  };
  osx64 = {
    file = "codeql-osx64.zip";
    hash = "sha256-YcXStT4c2O4r1XwxpVxXr1P/qv3xnEbSNBcExsrPNdM=";
  };

  # CodeQL does not offer ARM64 builds for Linux (github/codeql#20616), so we
  # resort to x86_64 emulation instead. macOS releases include both AMD64 and
  # ARM64 support, mitigating the need for emulation.
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

  # The Linux archive names its tracer lib64trace.so and bundles an x86_64 JDK
  # that will not run from a Nix store.
  linuxFixup = ''
    ln -sf $out/codeql/tools/linux64/lib64trace.so $out/codeql/tools/linux64/libtrace.so
    rm -rf $out/codeql/tools/linux64/java
    ln -s ${pkgs.zulu17} $out/codeql/tools/linux64/java
  '';

  # Wrapping all executables around QEMU to achieve x86_64 emulation. Shared
  # objects are unmodified to avoid caller dlopen() breakage.
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

    src = pkgs.fetchurl {
      url = "https://github.com/github/codeql-cli-binaries/releases/download/v${version}/${target.asset.file}";
      inherit (target.asset) hash;
    };

    nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [
      pkgs.unzip
      pkgs.file
    ];

    installPhase = ''
      runHook preInstall

      mkdir -p $out/codeql $out/bin
      cp -R * $out/codeql/
      ${lib.optionalString (target.dir == "linux64") linuxFixup}
      ln -s $out/codeql/codeql $out/bin/

      runHook postInstall
    '';

    # Emulation is applied in postFixup instead of installPhase to avoid
    # getting mangled by autopatchelf
    postFixup = (old.postFixup or "") + lib.optionalString target.emulate emulateFixup;
  });
in
{
  packages = [ codeql ];
}
