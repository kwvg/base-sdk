# The shell CI runs in, and nothing more than CI needs

# Every package reaches this through a mod that names its caller in `maint/`
# or a workflow step.

{ compose, mods, ... }:

compose [
  mods.rust
  mods.cxx
  mods.python
  mods.nixpkgs
  mods.codeql
]
