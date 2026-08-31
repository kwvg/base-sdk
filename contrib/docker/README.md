# Docker

The devshells in [`contrib/nix`](../nix) are the toolchain this repository
builds against, and they need Nix. This carries Nix instead, so a host that has
only Docker still gets the same shell, and a macOS or Windows host gets the
Linux one CI uses. There is no separate build environment to reconcile it
against: the devshell is the environment, and this is a way into it.

## Usage Guide

```bash
cd contrib/docker
docker compose build
HOST_UID=$(id -u) HOST_GID=$(id -g) docker compose run --rm nix_shell
```

Pass `HOST_UID` and `HOST_GID` so that anything written to your working tree
belongs to you; both default to `1000`. Exporting them from your
`~/.bash_profile`, `~/.zshrc` or a `.env` file beside this one saves repeating
them.

That is the whole interface: it drops you straight into the devshell. There
is nothing to run once you are in, and nothing to learn, and no choice to
make. It enters `#dev`, the broadest shell the flake offers, because a
container for checking that things work should be checking the widest surface
there is.

Arguments run in the shell rather than replacing it, so a script asks for what
it wants without an interactive step:

```bash
docker compose run --rm nix_shell cargo build --workspace
```

### Why two services

Nix owns `/nix` as root, but a container writing to a bind mount as root
leaves root-owned files in your tree. So `nix_daemon` is the only root
container and the only one holding the store, while `nix_shell` runs as you
and asks the daemon to build. `depends_on` starts the daemon first, and the
shell waits for its socket before doing anything.

`depends_on` gates the shell on the daemon's healthcheck rather than on it
merely having started, so the socket exists before nix is run and a daemon
that never comes up fails the run in ten seconds instead of hanging. Both
services set `init: true`, which puts Docker's own init at PID 1 to reap
orphans and forward signals; nothing is added to the image for it.

The daemon keeps running after the shell exits, which is what makes a second
`docker compose run` cheap. To stop it:

```bash
docker compose down
```

### First run is slow

`docker compose build` is quick, because the image is only Nix and two scripts.
Entering a shell is not: it leaves the store volume around 11 GiB. That is
cached there afterwards, so the cost is paid once and survives
`docker compose down`.

To reclaim that space:

```bash
docker compose down --volumes
```

### What it does with your files

The repository is bind-mounted at `/src/base-sdk`, so edits on either side are
immediately visible on the other. `CARGO_TARGET_DIR` and `CARGO_HOME` point
into the `build_cache` volume rather than the mount, which keeps build
artifacts out of your tree and keeps them between runs.
