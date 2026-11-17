# vsftpd victim built from the pinned Alpine base: pinned, multi-arch, nothing pulled at run time.
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
RUN apk add --no-cache vsftpd \
    && adduser -D -h /home/testuser testuser && echo 'testuser:testpass' | chpasswd \
    && mkdir -p /var/run/vsftpd/empty && echo hello > /home/testuser/readme.txt
COPY vsftpd.conf /etc/vsftpd/vsftpd.conf
EXPOSE 21
CMD ["vsftpd", "/etc/vsftpd/vsftpd.conf"]
