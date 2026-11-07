#!/usr/bin/env bash
# ==============================================================================
# LCP Minecraft Server Gateway Deployment Script (Linux x86_64)
# Protocol: LCP (Lightweight Custom Protocol) v1.2.1-FINAL
# Ports: UDP 856 (Strict TLS 1.3), UDP 855 (SPKI Pinning Disaster Recovery)
# Target: Minecraft Server (TCP 127.0.0.1:25565)
# ==============================================================================
set -euo pipefail

INSTALL_DIR="/opt/lcp-mc-server"
CERT_DIR="$INSTALL_DIR/certs"
SYSTEMD_FILE="/etc/systemd/system/lcp-mc-server.service"

echo ">>> [1/5] 创建安装目录: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
mkdir -p "$CERT_DIR"

if [ -f "./lcp-mc-server-linux" ]; then
    cp ./lcp-mc-server-linux "$INSTALL_DIR/lcp-mc-server-linux"
elif [ -f "./bin/lcp-mc-server-linux" ]; then
    cp ./bin/lcp-mc-server-linux "$INSTALL_DIR/lcp-mc-server-linux"
else
    echo "[-] 未找到 lcp-mc-server-linux 二进制文件，请将编译出的二进制文件放在当前目录。"
    exit 1
fi
chmod +x "$INSTALL_DIR/lcp-mc-server-linux"

echo ">>> [2/5] 检查/生成 855 端口 SPKI 专用灾备长效证书 (ECDSA P-256, 10年有效期)"
DISASTER_CERT="$CERT_DIR/disaster.crt"
DISASTER_KEY="$CERT_DIR/disaster.key"

if [ ! -f "$DISASTER_CERT" ] || [ ! -f "$DISASTER_KEY" ]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -days 3650 -nodes \
        -keyout "$DISASTER_KEY" \
        -out "$DISASTER_CERT" \
        -subj "/CN=lcp-mc-disaster" \
        -addext "subjectAltName=DNS:lcp-mc-disaster,IP:127.0.0.1"
    echo "[+] 灾备证书生成完毕。"
else
    echo "[*] 已存在灾备证书，跳过生成。"
fi

# 计算标准 SPKI SHA-256 公钥指纹
SPKI_HEX=$(openssl x509 -in "$DISASTER_CERT" -noout -pubkey | openssl pkey -pubin -outform DER | sha256sum | awk '{print $1}')
echo ""
echo "================================================================================"
echo " [重要] UDP 855 端口专属灾备 SPKI 公钥指纹 (SHA-256 Hex):"
echo " >> $SPKI_HEX <<"
echo " 请将此指纹配置到客户端或启动器中！"
echo "================================================================================"
echo ""

echo ">>> [3/5] 开放安全组与系统防火墙 UDP 856 与 UDP 855 端口"
if command -v ufw >/dev/null 2>&1; then
    ufw allow 856/udp comment 'LCP QUIC Strict Port' || true
    ufw allow 855/udp comment 'LCP QUIC Disaster Port' || true
    echo "[+] UFW 规则已更新。"
fi

if command -v iptables >/dev/null 2>&1; then
    iptables -I INPUT -p udp --dport 856 -j ACCEPT || true
    iptables -I INPUT -p udp --dport 855 -j ACCEPT || true
    echo "[+] iptables 规则已添加。"
fi

echo ">>> [4/5] 安装 systemd 守护进程服务"
cat <<EOF > "$SYSTEMD_FILE"
[Unit]
Description=LCP Minecraft Server Gateway (QUIC UDP 856/855 -> TCP 25565)
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/lcp-mc-server-linux \\
  -port-strict=856 \\
  -port-disaster=855 \\
  -target=127.0.0.1:25565 \\
  -proxy-protocol=true \\
  -cert-strict=/etc/letsencrypt/live/mc.potatolight.cn/fullchain.pem \\
  -key-strict=/etc/letsencrypt/live/mc.potatolight.cn/privkey.pem \\
  -cert-disaster=$DISASTER_CERT \\
  -key-disaster=$DISASTER_KEY
Restart=always
RestartSec=5s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable lcp-mc-server.service
echo "[+] 服务已注册为系统服务并开启自启。"

echo ">>> [5/5] 启动服务并检查运行状态"
systemctl restart lcp-mc-server.service
sleep 1
systemctl status lcp-mc-server.service --no-pager || true

echo ""
echo "================================================================================"
echo " LCP Minecraft Server 网关部署完成！"
echo " - UDP 856: Strict TLS 1.3 生产端口 (Let's Encrypt / 公共 CA 证书)"
echo " - UDP 855: SPKI Pinning 容灾应急端口 (指纹: $SPKI_HEX)"
echo " - TCP 25565: 本地 Minecraft 服务器 (带 HAProxy Proxy Protocol v2 真实玩家 IP 传递)"
echo "================================================================================"
