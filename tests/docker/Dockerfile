# Test image: the Debian 13 packages PSPM uses, without systemd.
FROM debian:trixie
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      nginx libnginx-mod-http-lua luajit \
      php8.4-cli php8.4-fpm php8.4-pgsql php8.4-mbstring php8.4-curl php8.4-intl \
      openssl ca-certificates curl jq iproute2 procps \
    && rm -rf /var/lib/apt/lists/*
