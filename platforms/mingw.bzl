"""The MinGW-w64 sysroot, taken from the devshell."""

# The sysroot sits at a store path `MODULE.bazel` cannot spell, so this rule
# turns the environment into a label, as `sdk.bzl` does for macOS.

def _mingw_sysroot_impl(rctx):
    path = rctx.getenv(_SYSROOT_ENV, "")

    # An absent sysroot is not an error; only an action that needs it fails.
    if path:
        for name in _DIRS:
            rctx.symlink(path + "/" + name, name)

    rctx.file("BUILD.bazel", _BUILD)

_SYSROOT_ENV = "MINGW_SYSROOT"

# Where the headers, libraries and GCC runtime sit in the sysroot.
_DIRS = [
    "include",
    "lib",
    "x86_64-w64-mingw32",
]

# The files must be declared for a sandboxed action to see them.
_BUILD = """\
filegroup(
    name = "sysroot",
    srcs = glob(
        [
            "include/**",
            "lib/**",
            "x86_64-w64-mingw32/**",
        ],
        allow_empty = True,
    ),
    visibility = ["//visibility:public"],
)
"""

mingw_sysroot = repository_rule(
    implementation = _mingw_sysroot_impl,
    environ = [_SYSROOT_ENV],
    # Re-run when the environment changes, not only when the rule does.
    configure = True,
    doc = "Exposes the devshell's MinGW-w64 sysroot as a label.",
)
