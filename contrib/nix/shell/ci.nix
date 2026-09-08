# Development shell for continuous integration

{
  compose,
  crossTargets,
  cxx,
  mods,
  ...
}:

compose [
  (cxx.forTargets crossTargets)
  mods.codeql
  mods.cxx
  mods.nixpkgs
  mods.python
  mods.rust
]
