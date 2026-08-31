# Note: 'docker compose up' will leave you hanging, you need to use
#       'docker compose run nix_shell' to drop into an interactive shell

# Pinned by digest: this is nix 2.35.2, and the tag moves.
FROM nixos/nix@sha256:7a007c766426c1877758ddc5cb87a965ac131fc78c582ce0083d922d51ae945c

# The base image ships no bash at /bin/bash; /bin/sh already is one.
SHELL ["/bin/sh", "-c"]

# The flake commands the devshell needs are still experimental, and the base
# image does not enable them. Its config is a symlink into the read-only store
# and carries the trusted key for cache.nixos.org, so replace the link with a
# copy and append: clobbering it would substitute nothing and build all of it.
RUN base="$(readlink -f /etc/nix/nix.conf)" \
    && rm /etc/nix/nix.conf \
    && install -m 0644 "$base" /etc/nix/nix.conf \
    && printf '%s\n' 'experimental-features = nix-command flakes' \
      >> /etc/nix/nix.conf

# The base image's PATH has no /usr/local/bin, where the scripts below land.
ENV PATH="/usr/local/bin:$PATH"

# The shell service runs as the host's user and cannot write the bind mount's
# parent, so both of these point at a volume the daemon hands over.
ENV CARGO_HOME="/build/cargo" \
    CARGO_TARGET_DIR="/build/target"

COPY ./scripts/daemon     /usr/local/bin/daemon
COPY ./scripts/entrypoint /usr/local/bin/entrypoint

RUN chmod 0755 \
      /usr/local/bin/daemon \
      /usr/local/bin/entrypoint

WORKDIR "/src/base-sdk"

ENTRYPOINT ["/usr/local/bin/entrypoint"]
