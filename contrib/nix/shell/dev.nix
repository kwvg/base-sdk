# The CI shell, and what a developer wants on top of it

# Mutates ci rather than composing a list of its own, so it cannot drift from
# what CI has. Nothing is added yet; this is where the heavy pieces go that a
# runner has no reason to download.

{ ci, ... }:

ci.overrideAttrs (_: { })
