FROM nixos/nix:2.35.2

SHELL ["/bin/sh", "-c"]

ENV PATH="/usr/local/bin:$PATH"

RUN rm /etc/nix/nix.conf

COPY ./nix.conf   /etc/nix/nix.conf
COPY ./daemon     /usr/local/bin/daemon
COPY ./entrypoint /usr/local/bin/entrypoint

RUN chmod +x /usr/local/bin/daemon /usr/local/bin/entrypoint

ARG HOST_UID=1000
ARG HOST_GID=1000

RUN printf 'nixuser:x:%s:\n' "${HOST_GID}" >> /etc/group \
 && printf 'nixuser:x:%s:%s:Nix user:/var/cache/base-sdk/home:/bin/sh\n' \
      "${HOST_UID}" "${HOST_GID}" >> /etc/passwd

WORKDIR "/src/base-sdk"

ENTRYPOINT ["/usr/local/bin/entrypoint"]
