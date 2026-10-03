"""Flags shared by every Bazel-built Rust target."""

# rules_rust ignores `[lints]`, so the workspace denies are restated here.
# Clippy lints are omitted, as plain rustc rejects them.
RUSTC_LINTS = [
    "-Dunsafe_code",
    "-Dunused_must_use",
    "-Dmissing_debug_implementations",
    "-Dnon_ascii_idents",
    "-Dkeyword_idents",
    "-Drust_2021_incompatible_closure_captures",
    "-Drust_2021_incompatible_or_patterns",
]

# Mirrors `[profile.dev]` and `[profile.release]`, chosen by `--build_profile`.
# The bitcode flag LTO needs is global, in `.bazelrc`.
PROFILE_RUSTC_FLAGS = select({
    "//:build_profile_debug": [
        "-Copt-level=0",
        "-Cdebuginfo=2",
        "-Ccodegen-units=1",
        "-Coverflow-checks=yes",
        "-Cdebug-assertions=yes",
    ],
    "//:build_profile_release": [
        "-Copt-level=3",
        "-Clto=fat",
        "-Cstrip=symbols",
        "-Cpanic=abort",
    ],
})
