# The CI shell, plus every cross target the host can reach

# Mutates ci rather than composing a list of its own, so it cannot drift
# from what CI has. Each sysroot it adds is another gigabyte or so, which is
# why a runner does not enter this.

{
  ci,
  cxx,
  crossTargets,
  nightlyWith,
  ...
}:

let
  cross = cxx.forTargets crossTargets;
  toolchain = nightlyWith crossTargets;
in

ci.overrideAttrs (
  old:
  {
    # mkShell puts `packages` here.
    nativeBuildInputs = old.nativeBuildInputs ++ cross.packages ++ [ toolchain ];

    # ci put its own nightly on PATH and both are now in it, so this one goes
    # in front rather than trying to take the other out. Same channel; this is
    # the one that also carries a std per cross target.
    shellHook = (old.shellHook or "") + ''
      export PATH="${toolchain}/bin:$PATH"
    '';
  }
  // cross.env
)
