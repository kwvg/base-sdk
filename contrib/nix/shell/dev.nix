# Development shell for interactive instances

{
  ci,
  cxx,
  crossTargets,
  foreignTargets,
  lib,
  nightlyWith,
  pkgs,
  ...
}:

let
  cross = cxx.forTargets foreignTargets;
  toolchain = nightlyWith (crossTargets ++ foreignTargets);

  ohMyBash = pkgs.fetchFromGitHub {
    owner = "ohmybash";
    repo = "oh-my-bash";
    rev = "abf846186ab0a8a41ec5888e827ece6277dfe446";
    hash = "sha256-tlYKhz7baZ02FcHlYMnLQsgjEsN/K+z3+UWre4mS5Qs=";
  };

  tmuxConf = pkgs.writeText "tmux.conf" ''
    set -g default-terminal "tmux-256color"
    set -ga terminal-overrides ",xterm-256color:Tc"
    set -g alternate-screen off
    set -g base-index 1
    set -g detach-on-destroy on
    set -g history-limit 20000
    set -g mouse on
    set -g pane-base-index 1
    set -g renumber-windows on
  '';

  # tmux reads a file named on its command line or one under $HOME, and a
  # devshell owns neither, so the flag is bound to the binary instead.
  tmux = pkgs.writeShellScriptBin "tmux" ''
    exec ${pkgs.tmux}/bin/tmux -f ${tmuxConf} "$@"
  '';

  utilities = [
    pkgs.bashInteractive
    pkgs.curl
    pkgs.dnsutils
    pkgs.fd
    pkgs.gh
    pkgs.gnupg
    pkgs.jq
    pkgs.nano
    pkgs.pv
    pkgs.ripgrep
    pkgs.rsync
    pkgs.unzip
    pkgs.wget
    tmux
  ]
  # Darwin carries `ping` in its base system, Linux does not.
  ++ lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.iputils ];
in

ci.overrideAttrs (
  old:
  {
    # mkShell places `packages` here.
    nativeBuildInputs = old.nativeBuildInputs ++ cross.packages ++ utilities ++ [ toolchain ];

    # oh-my-bash is meant for interactive use. `--command` has no use for it.
    shellHook = (old.shellHook or "") + ''
      export PATH="${toolchain}/bin:$PATH"

      export OSH="${ohMyBash}"
      if [[ $- == *i* ]]; then
        OSH_THEME="rr"
        source "$OSH/oh-my-bash.sh"
      fi
    '';
  }
  // cross.env
)
