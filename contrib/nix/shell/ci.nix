# Development shell for continuous integration

{ compose, mods, ... }:

compose [
  mods.codeql
  mods.cxx
  mods.nixpkgs
  mods.python
  mods.rust
]
