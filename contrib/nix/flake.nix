# Development shells shared by CI and a developer

# Callers name ./contrib/nix; a bare nix develop will not find it. Nix copies
# the whole tree in wherever the flake sits, so files above resolve by path,
# but self points here and cannot reach them.

{
  description = "Development shells for the Dash base SDK";

  inputs = {
    # 26.05, not unstable: 26.11 dropped x86_64-darwin, named in systems.
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    pyproject-nix = {
      url = "github:pyproject-nix/pyproject.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    uv2nix = {
      url = "github:pyproject-nix/uv2nix";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.pyproject-nix.follows = "pyproject-nix";
    };
    pyproject-build-systems = {
      url = "github:pyproject-nix/build-system-pkgs";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.uv2nix.follows = "uv2nix";
    };
  };

  outputs =
    {
      nixpkgs,
      rust-overlay,
      ...
    }@inputs:
    let
      inherit (nixpkgs) lib;

      # No Windows: Nix does not run there, so it is cross-built instead.
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      eachSystem =
        f:
        lib.genAttrs systems (
          system:
          f (
            import nixpkgs {
              inherit system;
              overlays = [ rust-overlay.overlays.default ];
              # CodeQL's CLI is unfree; allowed by name so anything else
              # unfree a later edit reaches for still has to argue for it.
              config.allowUnfreePredicate = pkg: builtins.elem (lib.getName pkg) [ "codeql" ];
            }
          )
        );
    in
    {
      devShells = eachSystem (
        pkgs:
        let
          ctx = import ./shell/common.nix {
            inherit pkgs lib inputs;
            root = ../..;
          };
          ci = import ./shell/ci.nix ctx;
        in
        {
          inherit ci;
          dev = import ./shell/dev.nix (ctx // { inherit ci; });
        }
      );

      formatter = eachSystem (pkgs: pkgs.nixfmt);
    };
}
