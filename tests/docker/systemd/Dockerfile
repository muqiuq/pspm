# A Debian 13 "box" with systemd as PID 1, for running install.sh end to end.
FROM debian:trixie
ENV container=docker
RUN apt-get update && apt-get install -y --no-install-recommends systemd systemd-sysv dbus iproute2 procps \
      openssh-server sudo ca-certificates curl git && rm -rf /var/lib/apt/lists/*
RUN systemctl mask getty@tty1.service systemd-udevd.service systemd-networkd-wait-online.service 2>/dev/null; true
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
