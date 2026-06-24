FROM bkimminich/juice-shop:v15.0.0 AS juice_src

# Node 18 base 与 juice-shop native bindings 兼容
FROM node:18-bookworm-slim

# 1. 装 sysdig + 攻击工具
# Debian 仓库的 sysdig 0.27 在 Docker Desktop 上能 fallback BPF 模式
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl wget gnupg \
        && curl -s https://download.sysdig.com/DRAIOS-GPG-KEY.public | apt-key add - \
        && echo "deb https://download.sysdig.com/stable/deb stable-$(dpkg --print-architecture)/" > /etc/apt/sources.list.d/draios.list \
        && apt-get update || true

RUN apt-get install -y --no-install-recommends \
        strace sysdig dkms \
        auditd \
        sqlmap nmap hydra-gtk \
        procps net-tools iproute2 dnsutils \
        postgresql-client jq \
        ca-certificates \
        && rm -rf /var/lib/apt/lists/*

# 2. 直接拷已编译好的 juice-shop（与 node 18 ABI 一致）
COPY --from=juice_src /juice-shop /opt/juice-shop

# 3. entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 3000

CMD ["/entrypoint.sh"]
