FROM myoung34/github-runner:2.334.0-ubuntu-noble

ENV DEBIAN_FRONTEND=noninteractive
ENV RUNNER_HOME=/home/runner
ENV PATH=/home/runner/.nix-profile/bin:/nix/var/nix/profiles/default/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV NIX_CONFIG="experimental-features = nix-command flakes"

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN set -eux; \
    for home in /home/runner /root; do \
      install -d "${home}/.config/nix"; \
      printf '%s\n' \
        'experimental-features = nix-command flakes' \
        'sandbox = false' \
        'build-users-group =' \
        'max-jobs = 8' \
        'cores = 8' \
        > "${home}/.config/nix/nix.conf"; \
    done; \
    chown -R runner:runner /home/runner/.config

RUN set -eux; \
    install -d -o runner -g runner /nix /home/runner/tmp; \
    curl -fsSLo /tmp/install-nix.sh https://nixos.org/nix/install; \
    HOME=/home/runner USER=runner TMPDIR=/home/runner/tmp gosu runner sh /tmp/install-nix.sh --no-daemon; \
    rm /tmp/install-nix.sh
