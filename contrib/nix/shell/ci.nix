# Development shell for continuous integration

{ compose, mods, ... }:

compose [
  mods.cxx
  mods.nixpkgs
  mods.python
  mods.rust
]
