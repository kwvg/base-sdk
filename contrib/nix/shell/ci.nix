# Development shell for continuous integration

{ compose, mods, ... }:

compose [
  mods.nixpkgs
  mods.python
  mods.rust
]
