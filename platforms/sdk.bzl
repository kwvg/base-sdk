"""The macOS sysroot, taken from the devshell instead of from Xcode."""

# `llvm.sysroot` takes a path or a label, and the SDK sits at a store path that
# `MODULE.bazel` cannot spell. This rule turns the environment into a label.

def _macos_sdk_impl(rctx):
    path = rctx.getenv(_SYSROOT_ENV, "")

    # An absent SDK is not an error; only an action that needs it fails.
    if path:
        rctx.symlink(path + "/usr", "usr")

        # Sandboxed actions stage every file, so link only the frameworks used.
        # Link each one, as a glob of the directory walks self-referential
        # headers.
        for name in _FRAMEWORKS_USED:
            rctx.symlink(path + "/" + _FRAMEWORKS + "/" + name + ".framework", _FRAMEWORKS + "/" + name + ".framework")

    rctx.file("BUILD.bazel", _BUILD)

_SYSROOT_ENV = "MACOS_SDK_SYSROOT"

_FRAMEWORKS = "System/Library/Frameworks"

# `toolchains_llvm` links Foundation into every Darwin binary, and Foundation
# re-exports CoreFoundation. Add a name when a `-sys` crate needs another.
_FRAMEWORKS_USED = [
    "CoreFoundation",
    "Foundation",
]

# The files must be declared for a sandboxed action to see them.
_BUILD = """\
filegroup(
    name = "sysroot",
    srcs = glob(
        [
            "System/**",
            "usr/**",
        ],
        allow_empty = True,
    ),
    visibility = ["//visibility:public"],
)
"""

macos_sdk = repository_rule(
    implementation = _macos_sdk_impl,
    environ = [_SYSROOT_ENV],
    # Re-run when the environment changes, not only when the rule does.
    configure = True,
    doc = "Exposes the devshell's macOS SDK as a sysroot label.",
)
