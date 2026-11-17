# FTP victim: ProFTPD on a pinned Debian base: pinned, multi-arch, nothing pulled at run time.
# Not vsftpd: it segfaulted intermittently (exit 139) under repeated failed logins on an arm64
# Linux host, both as Alpine (musl) and Debian (glibc) builds.
FROM debian:12-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends proftpd-core \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -s /bin/bash testuser && echo 'testuser:testpass' | chpasswd \
    && echo hello > /home/testuser/readme.txt
COPY proftpd.conf /etc/proftpd/proftpd.conf
EXPOSE 21
CMD ["proftpd", "--nodaemon", "-c", "/etc/proftpd/proftpd.conf"]
