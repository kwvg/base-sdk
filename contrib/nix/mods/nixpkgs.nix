# Packages taken from nixpkgs as they come, with nothing to configure

# One mod for everything that is only a name in a package set. A package earns
# a file of its own when it needs work done to it, which is what the other
# mods here are: an install phase rewritten, a driver built, a lock resolved.

{ pkgs }:

{
  packages = [
    # git is not a convenience: common.py requires it, lint_unconv.py reads
    # its commit range through it, and pymarkdownlnt honours the ignore file
    # only by asking git. Absent, that check silently lints the virtualenv.
    pkgs.git

    # What lint_nix.py holds the .nix files to, and what nix fmt runs.
    pkgs.nixfmt

    # The `tools` extra of pyproject.toml, from nixpkgs rather than the lock;
    # the two disagree on versions and that is accepted. pymarkdownlnt is
    # absent from nixpkgs, so it stays in the lock under `lib`.
    pkgs.ruff
    pkgs.semgrep
    pkgs.taplo
    pkgs.zensical

    # lint_javascript.py reaches eslint through npx. pnpm rather than npm so a
    # lockfile pins the tree; nixpkgs pins pnpm itself. Node 24 is the active
    # LTS line; 22 has been maintenance-only since October 2025.
    pkgs.nodejs_24
    pkgs.pnpm
  ];
}
