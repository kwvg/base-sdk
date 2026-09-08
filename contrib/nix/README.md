<!-- [start:header] -->

## Nix

To maintain a consistent development environment and reproducible toolchain, a declarative environment is available
using [Nix](https://nixos.org) on macOS and Linux hosts on ARM64 and AMD64. **Windows users are recommended to either
resort to using Nix through [Windows Subsystem for Linux](https://github.com/microsoft/WSL) or manually set up their
environment.**

<!-- [end:header] -->

<!-- [start:body] -->

### Setting up Nix

> [!WARNING]
>
> macOS 26 "Tahoe" is the last release supporting Intel-based Macs
> ([source](https://developer.apple.com/videos/play/wwdc2025/102/?time=3296)). Support for it as a _host_ is on a
> best-effort basis while it is still an officially supported _target_ platform. `nixpkgs` dropped `x86_64-darwin`
> per [NixOS/nixpkgs#535508](https://github.com/NixOS/nixpkgs/pull/535508) (included in 26.11).
>
> The environment is therefore pinned to its prior release, 26.05, and will stay there for as long as it remains
> reasonable.

For install guidance on Linux, see [here](https://nixos.org/download/#nix-install-linux). For macOS, while Nix is an
option, Determinate Nix has been found to better accommodate macOS-specific quirks and guidance for that is available
[here](https://docs.determinate.systems/determinate-nix/#getting-started). That being said, regardless of choice of Nix
distribution used (including independent projects like [Lix](https://lix.systems/install/)), `nix-command` and `flakes`
features need to be enabled (guidance for enablement should be taken from your distribution vendor).

### Entering a shell

To enter an interactive shell, from the repository root, use

```bash
nix develop ./contrib/nix#ci
```

### One-shot commands

To execute a command _without_ switching to a shell; or for scripting, use

```bash
nix develop ./contrib/nix#ci --command cargo test --workspace --features full
```

<!-- [end:body] -->
