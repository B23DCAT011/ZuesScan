# A deliberately outdated SSH server: OpenSSH 7.5p1 (Alpine 3.7, end of life), which is
# affected by CVE-2018-15473 (username enumeration). Lab use only, on an isolated network.
# No account can log in: no password is set and no key is installed.
FROM alpine:3.7@sha256:8421d9a84432575381bfabd248f1eb56f3aa21d9d7cd2511583c68c9b7511d10
RUN apk add --no-cache openssh \
 && ssh-keygen -A \
 && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
