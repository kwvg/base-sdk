## Docker

> [!TIP]
> On some platforms, `docker compose` is not included with the baseline Docker installation. In that case, you may
> need to consult platform-specific guidance on installing Compose, like the
> [`docker-compose`](https://packages.debian.org/trixie/docker-compose) package on Debian.

To install Docker on your host, see [official guidance](https://docs.docker.com/get-started/get-docker/) for your
platform. Note that unlike using Nix, the store used in Docker _cannot_ be shared with the host and using the provided
containers is highly discouraged if you already use Nix on your host.

**The Nix store is persisted as the volume `nix_store` and is expected to consume 15-20GB at a minimum, it is managed
by the `nix_daemon` container and other Nix daemons must not compete for management of this store.**

> [!WARNING]
> The workspace is bind-mounted and the Compose project is incompatible with worktrees. If you are using paired
> programming assistants like Claude Code or Codex, there is a fair chance worktrees are in use. Worktrees resolve
> their parent repository by absolute path on the host, which isn't visible from the vantage point of the container.

To build the image, from the [`contrib/docker`](.) directory, run

```bash
docker compose build
```

### Entering a shell

> [!NOTE]
> To prevent permissions issues, `HOST_UID` and `HOST_GID` are supplied to ensure that the container uses the same
> UID:GID pair as the source code it is bind-mounted against. If undefined, they default to the default Linux pair,
> `1000:1000`.

To enter an interactive shell, from the [`contrib/docker`](.) directory, run

```bash
# Starts the containers and drops you into an interactive shell, reaped on exit. The daemon is left running
HOST_UID=$(id -u) HOST_GID=$(id -g) docker compose run --rm nix_shell
```

To shut down the daemon, from the [`contrib/docker`](.) directory, run

```bash
docker compose down
```

### One-shot commands

To execute a command _without_ switching to a shell; or for scripting, from the [`contrib/docker`](.) directory, run

```bash
docker compose run --rm nix_shell cargo build --workspace
```

### Reaping the Nix store

To get rid of the persistent store and the build cache, freeing the associated space, from the
[`contrib/docker`](.) directory, run

```bash
docker compose down --volumes
```
