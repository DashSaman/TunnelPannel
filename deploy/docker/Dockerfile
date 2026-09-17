FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive TZ=Asia/Tehran

RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-venv python3-pip iproute2 wireguard-tools nftables iptables \
      strongswan xl2tpd openvpn openssh-server autossh curl jq socat kmod openssl \
      iputils-ping netcat-openbsd procps psmisc ca-certificates && \
    python3 -m venv /opt/mtf-venv && \
    /opt/mtf-venv/bin/pip install --no-cache-dir fastapi uvicorn jinja2 python-multipart httpx paramiko && \
    apt-get clean && rm -rf /var/lib/apt/lists/* && \
    echo 'exit 101' > /usr/sbin/policy-rc.d && chmod +x /usr/sbin/policy-rc.d

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 9443
ENTRYPOINT ["/entrypoint.sh"]
