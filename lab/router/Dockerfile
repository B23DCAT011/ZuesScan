# The lab's router: forwards between the DMZ and the internal network and masquerades,
# so that a scan from the DMZ crosses a real hop (traceroute shows it on the map).
# Also used once by the worker's route sidecar (`ip route`).
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
RUN apk add --no-cache iptables iproute2
COPY router.sh /usr/local/bin/router.sh
ENTRYPOINT ["sh", "/usr/local/bin/router.sh"]
