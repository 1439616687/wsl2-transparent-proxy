#!/usr/bin/env bash
# WSL2 Transparent Proxy (redsocks + iptables) One-Key Installer
# Author: chatGPT
# Tested on: Ubuntu (WSL2) 20.04/22.04/24.04
set -Eeuo pipefail

#=============================#
#          常量与默认值        #
#=============================#
REDSOCKS_PORT=${REDSOCKS_PORT:-31338}
WIN_PROXY_PORT=${WIN_PROXY_PORT:-2080}
REDSOCKS_CONF="/etc/redsocks.conf"
REDSOCKS_LOG="/var/log/redsocks.log"
REDSOCKS_USER="redsocks"
REDSOCKS_GROUP="redsocks"
CHAIN_NAME="REDSOCKS"
MTU_VALUE=1400
HEALTH_URLS=("https://cp.cloudflare.com/generate_204" "https://www.microsoft.com" "https://detectportal.firefox.com/success.txt")
SERVICE_REDSOCKS="/etc/systemd/system/redsocks.service"
SERVICE_IPTABLES="/etc/systemd/system/wsl-redsocks-iptables.service"
SERVICE_MTU="/etc/systemd/system/wsl-mtu1400.service"
TIMER_HEALTH="/etc/systemd/system/proxy-health.timer"
SERVICE_HEALTH="/etc/systemd/system/proxy-health.service"
PROXYCTL="/usr/local/bin/proxyctl"
HEALTHCHECK="/usr/local/bin/proxy-healthcheck.sh"
ALIAS_FILE="/etc/profile.d/proxyctl-aliases.sh"
UNINSTALL="/usr/local/bin/proxyctl-uninstall.sh"

#=============================#
#          彩色输出工具        #
#=============================#
C_RESET="\033[0m"; C_BLUE="\033[1;34m"; C_GREEN="\033[1;32m"; C_YELLOW="\033[1;33m"; C_RED="\033[1;31m"
info(){ echo -e "${C_BLUE}[信息]${C_RESET} $*"; }
ok(){ echo -e "${C_GREEN}[完成]${C_RESET} $*"; }
warn(){ echo -e "${C_YELLOW}[警告]${C_RESET} $*"; }
err(){ echo -e "${C_RED}[错误]${C_RESET} $*" >&2; }

trap 'err "执行过程中出现错误。请滚动查看上方输出定位问题。"' ERR

require_root(){
  if [[ ${EUID} -ne 0 ]]; then
    err "请用 root 权限运行：sudo $0"
    exit 1
  fi
}

#=============================#
#        基础检查与安装        #
#=============================#
install_deps(){
  info "更新软件索引并安装依赖（redsocks、iptables、curl、netcat 等）..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y redsocks iptables iproute2 curl netcat-openbsd ca-certificates lsb-release
  ok "依赖安装完成。"
}

detect_win_ip(){
  # 通过默认路由网关获取 Windows 主机 IP（WSL2 中就是默认网关）
  local gw
  gw=$(ip route | awk '/^default via / {print $3; exit}')
  if [[ -z "${gw:-}" ]]; then
    # 回退方式：从 resolv.conf 第一行 nameserver
    gw=$(awk '/^nameserver /{print $2; exit}' /etc/resolv.conf || true)
  fi
  if [[ -z "${gw:-}" ]]; then
    err "无法自动获取 Windows 主机 IP。请检查网络或重启 WSL。"
    exit 1
  fi
  echo "$gw"
}

check_port_open(){
  local host="$1" port="$2"
  if ! timeout 3 bash -c "echo | nc -w2 ${host} ${port}" >/dev/null 2>&1 ; then
    err "无法连接到 Windows 代理 ${host}:${port}。请确认 Windows 代理已开启 Allow LAN 并监听端口 ${port}。"
    exit 1
  fi
}

detect_proxy_type(){
  local host="$1" port="$2"
  info "尝试识别 ${host}:${port} 是 SOCKS5 还是 HTTP 代理..."
  # 尝试 SOCKS5 握手：发送 0x05 0x01 0x00，期望返回 0x05 0x00/0x02
  if printf '\x05\x01\x00' | nc -w2 "$host" "$port" | head -c2 | od -An -t u1 | awk '{exit !(($1==5)&&($2==0 || $2==2))}'; then
    ok "识别为 SOCKS5。"
    echo "socks5"
    return
  fi
  # 尝试 HTTP CONNECT：发起 CONNECT 并期望 200/407 等响应码行
  if printf 'CONNECT www.example.com:443 HTTP/1.1\r\nHost: www.example.com:443\r\n\r\n' \
      | nc -w3 "$host" "$port" | head -n1 | grep -Eq 'HTTP/1\.[01] (200|407|302|301)'; then
    ok "识别为 HTTP CONNECT。"
    echo "http-connect"
    return
  fi
  warn "无法明确识别代理类型，默认使用 SOCKS5（常见于 sing-box/clash 的 2080 端口）。"
  echo "socks5"
}

ensure_user_group(){
  if ! id -u "$REDSOCKS_USER" >/dev/null 2>&1; then
    info "创建系统用户 ${REDSOCKS_USER}..."
    adduser --system --no-create-home --group "$REDSOCKS_USER"
  fi
}

write_redsocks_conf(){
  local proxy_ip="$1" proxy_port="$2" proxy_type="$3"
  info "写入 ${REDSOCKS_CONF}（类型：${proxy_type}，上游：${proxy_ip}:${proxy_port}）..."
  cat > "$REDSOCKS_CONF" <<EOF
base {
  log_debug = off;
  log_info = on;
  log = "file:${REDSOCKS_LOG}";
  daemon = on;
  redirector = iptables;
  user = ${REDSOCKS_USER};
  group = ${REDSOCKS_GROUP};
}

redsocks {
  local_ip = 127.0.0.1;
  local_port = ${REDSOCKS_PORT};
  ip = ${proxy_ip};
  port = ${proxy_port};
  type = ${proxy_type};
  // 连接/空闲超时，减少“僵尸连接”
  timeout = 10;
}
EOF
  touch "$REDSOCKS_LOG"
  chown "$REDSOCKS_USER:$REDSOCKS_GROUP" "$REDSOCKS_LOG" || true
  ok "已生成 ${REDSOCKS_CONF}。"
}

write_systemd_units(){
  info "配置 systemd 服务（redsocks / iptables / MTU / 健康检查）..."
  # redsocks
  cat > "$SERVICE_REDSOCKS" <<'EOF'
[Unit]
Description=redsocks transparent proxy daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/sbin/redsocks -c /etc/redsocks.conf
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

  # iptables 规则应用/清理
  cat > "$SERVICE_IPTABLES" <<EOF
[Unit]
Description=Apply iptables rules for transparent proxy
After=network-online.target redsocks.service
Wants=redsocks.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${PROXYCTL} apply-iptables
ExecStop=${PROXYCTL} flush-iptables

[Install]
WantedBy=multi-user.target
EOF

  # MTU 设置
  cat > "$SERVICE_MTU" <<EOF
[Unit]
Description=Set MTU ${MTU_VALUE} on eth0 (WSL2)
After=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/ip link set dev eth0 mtu ${MTU_VALUE}

[Install]
WantedBy=multi-user.target
EOF

  # 健康检查 service + timer
  cat > "$SERVICE_HEALTH" <<EOF
[Unit]
Description=Proxy health check and self-heal

[Service]
Type=oneshot
ExecStart=${HEALTHCHECK}
EOF

  cat > "$TIMER_HEALTH" <<'EOF'
[Unit]
Description=Run proxy health check every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s
Unit=proxy-health.service

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload || true
  ok "systemd 单元已写入。"
}

write_proxyctl(){
  info "生成管理命令 ${PROXYCTL} ..."
  cat > "$PROXYCTL" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
REDSOCKS_PORT=31338
REDSOCKS_CONF="/etc/redsocks.conf"
REDSOCKS_LOG="/var/log/redsocks.log"
REDSOCKS_USER="redsocks"
CHAIN_NAME="REDSOCKS"

BLUE="\033[1;34m"; GREEN="\033[1;32m"; YEL="\033[1;33m"; RED="\033[1;31m"; RST="\033[0m"
i(){ echo -e "${BLUE}[i]${RST} $*"; }
o(){ echo -e "${GREEN}[ok]${RST} $*"; }
w(){ echo -e "${YEL}[!]${RST} $*"; }
e(){ echo -e "${RED}[x]${RST} $*" >&2; }

get_win_ip(){
  ip route | awk '/^default via / {print $3; exit}'
}

ipt(){
  iptables "$@"
}

ensure_chain(){
  if ! ipt -t nat -S | grep -q "^-N ${CHAIN_NAME}$"; then
    ipt -t nat -N ${CHAIN_NAME}
  fi
  ipt -t nat -F ${CHAIN_NAME}
}

rule_add_once(){
  # 用 -C 检查是否已存在，避免重复
  if ! ipt "$@" -C >/dev/null 2>&1; then
    ipt "$@" -A
  fi
}

apply_iptables(){
  i "应用 iptables 透明代理规则..."
  ensure_chain
  WIN_IP=$(get_win_ip)
  if [[ -z "${WIN_IP:-}" ]]; then e "无法获取 Windows IP"; exit 1; fi

  # REDSOCKS 自定义链：排除内网/本机/广播/Windows 主机，再重定向 TCP 到 redsocks
  ipt -t nat -F ${CHAIN_NAME}
  ipt -t nat -A ${CHAIN_NAME} -d 0.0.0.0/8 -j RETURN
  ipt -t nat -A ${CHAIN_NAME} -d 10.0.0.0/8 -j RETURN
  ipt -t nat -A ${CHAIN_NAME} -d 127.0.0.0/8 -j RETURN
  ipt -t nat -A ${CHAIN_NAME} -d 169.254.0.0/16 -j RETURN
  ipt -t nat -A ${CHAIN_NAME} -d 172.16.0.0/12 -j RETURN
  ipt -t nat -A ${CHAIN_NAME} -d 192.168.0.0/16 -j RETURN
  ipt -t nat -A ${CHAIN_NAME} -d 224.0.0.0/4 -j RETURN
  ipt -t nat -A ${CHAIN_NAME} -d 240.0.0.0/4 -j RETURN
  ipt -t nat -A ${CHAIN_NAME} -d ${WIN_IP}/32 -j RETURN
  ipt -t nat -A ${CHAIN_NAME} -p tcp -j REDIRECT --to-ports ${REDSOCKS_PORT}

  # OUTPUT 链：仅本机发起的 TCP，排除 redsocks 用户与 lo
  RED_UID=$(id -u ${REDSOCKS_USER})
  rule_add_once -t nat -o OUTPUT -p tcp -m owner --uid-owner ${RED_UID} -j RETURN
  rule_add_once -t nat -o OUTPUT -p tcp -o lo -j RETURN
  # （可选）排除访问本地 127.0.0.1 的连接
  rule_add_once -t nat -o OUTPUT -p tcp -d 127.0.0.0/8 -j RETURN
  rule_add_once -t nat -o OUTPUT -p tcp -j ${CHAIN_NAME}

  # （可选）PREROUTING：处理进入本机的 TCP（例如其他容器/WSL 子系统流量）
  rule_add_once -t nat -o PREROUTING -p tcp -j ${CHAIN_NAME} || true

  o "iptables 规则已应用。"
}

flush_iptables(){
  i "清理 iptables 规则..."
  if ipt -t nat -S | grep -q "^-N ${CHAIN_NAME}$"; then
    ipt -t nat -D OUTPUT -p tcp -m owner --uid-owner $(id -u redsocks) -j ${CHAIN_NAME} >/dev/null 2>&1 || true
    ipt -t nat -D OUTPUT -p tcp -o lo -j RETURN >/dev/null 2>&1 || true
    ipt -t nat -D OUTPUT -p tcp -d 127.0.0.0/8 -j RETURN >/dev/null 2>&1 || true
    ipt -t nat -D OUTPUT -p tcp -j ${CHAIN_NAME} >/dev/null 2>&1 || true
    ipt -t nat -D PREROUTING -p tcp -j ${CHAIN_NAME} >/dev/null 2>&1 || true
    ipt -t nat -F ${CHAIN_NAME} || true
    ipt -t nat -X ${CHAIN_NAME} || true
  fi
  o "iptables 规则已清理。"
}

start(){
  systemctl enable --now redsocks.service >/dev/null 2>&1 || true
  systemctl enable --now wsl-redsocks-iptables.service >/dev/null 2>&1 || true
  systemctl enable --now wsl-mtu1400.service >/dev/null 2>&1 || true
  systemctl enable --now proxy-health.timer >/dev/null 2>&1 || true
  o "透明代理已启动。"
}

stop(){
  systemctl stop proxy-health.timer >/dev/null 2>&1 || true
  systemctl stop wsl-redsocks-iptables.service >/dev/null 2>&1 || true
  systemctl stop redsocks.service >/dev/null 2>&1 || true
  flush_iptables
  o "透明代理已停止。"
}

restart(){
  stop || true
  start
}

status(){
  echo "=== redsocks.service ==="
  systemctl --no-pager -l status redsocks.service || true
  echo
  echo "=== iptables REDSOCKS chain ==="
  iptables -t nat -S ${CHAIN_NAME} || echo "(未创建链)"
  echo
  echo "=== health timer ==="
  systemctl --no-pager -l status proxy-health.timer || true
}

test_conn(){
  # 通过透明代理直接 curl 外网，若返回 204 或 200 即基本可用
  local urls=("https://cp.cloudflare.com/generate_204" "https://www.microsoft.com" "https://detectportal.firefox.com/success.txt")
  for u in "${urls[@]}"; do
    echo "--- 测试: $u"
    if curl -I --max-time 10 -sS "$u" | head -n1; then
      o "成功访问：$u"
      exit 0
    fi
  done
  e "测试未通过，请查看日志：$REDSOCKS_LOG"
  exit 1
}

logs(){
  tail -n 200 -f "$REDSOCKS_LOG"
}

set_type(){
  local newtype="${1:-}"
  if [[ "$newtype" != "socks5" && "$newtype" != "http-connect" ]]; then
    e "用法：$0 set-type socks5|http-connect"
    exit 1
  fi
  sed -i "s/^  type = .*/  type = ${newtype};/" "$REDSOCKS_CONF"
  o "已切换类型为 ${newtype}。重启生效。"
}

usage(){
  cat <<USAGE
proxyctl 管理命令：
  start           启动透明代理并应用规则（含开机服务）
  stop            停止透明代理并清理规则
  restart         重启
  status          查看状态
  test            连通性测试
  logs            实时查看 redsocks 日志
  apply-iptables  仅应用 iptables 规则（系统服务调用）
  flush-iptables  仅清理 iptables 规则（系统服务调用）
  set-type <t>    切换上游类型：socks5 | http-connect
USAGE
}

case "${1:-}" in
  start) start ;;
  stop) stop ;;
  restart) restart ;;
  status) status ;;
  test) test_conn ;;
  logs) logs ;;
  apply-iptables) apply_iptables ;;
  flush-iptables) flush_iptables ;;
  set-type) set_type "${2:-}" ;;
  *) usage ;;
esac
EOF
  chmod +x "$PROXYCTL"
  ok "已安装管理命令：$PROXYCTL"
}

write_healthcheck(){
  info "写入健康检查脚本 ${HEALTHCHECK} ..."
  cat > "$HEALTHCHECK" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
URLS=("https://cp.cloudflare.com/generate_204" "https://www.microsoft.com" "https://detectportal.firefox.com/success.txt")
log(){ logger -t proxy-health "$*"; echo "$(date '+%F %T') proxy-health: $*"; }
ok=0
for u in "${URLS[@]}"; do
  if curl -s --max-time 8 "$u" >/dev/null; then
    ok=1; break
  fi
done
if [[ $ok -eq 1 ]]; then
  log "OK"
  # 定期刷新连接池，避免僵尸连接：运行时间超过 1 天则重启 redsocks（温和策略）
  UPTIME=$(awk '{print int($1)}' /proc/uptime)
  if (( UPTIME > 86400 )); then
    systemctl restart redsocks.service || true
    log "redsocks restarted for pool refresh"
  fi
  exit 0
else
  log "failed, attempting self-heal..."
  systemctl restart redsocks.service || true
  /usr/local/bin/proxyctl apply-iptables || true
  sleep 2
  for u in "${URLS[@]}"; do
    if curl -s --max-time 8 "$u" >/dev/null; then
      log "recovered"
      exit 0
    fi
  done
  log "still failing"
  exit 1
fi
EOF
  chmod +x "$HEALTHCHECK"
  ok "健康检查脚本已创建。"
}

write_aliases(){
  info "写入中文/英文快捷命令别名 ..."
  cat > "$ALIAS_FILE" <<'EOF'
# proxyctl aliases
alias proxy-on='sudo proxyctl start'
alias proxy-off='sudo proxyctl stop'
alias proxy-status='sudo proxyctl status'
alias proxy-test='sudo proxyctl test'
# 中文别名
alias 代理开='sudo proxyctl start'
alias 代理关='sudo proxyctl stop'
alias 状态='sudo proxyctl status'
alias 测试='sudo proxyctl test'
EOF
  ok "已写入 /etc/profile.d/proxyctl-aliases.sh（重新开终端生效）。"
}

write_uninstall(){
  info "写入卸载脚本 ${UNINSTALL} ..."
  cat > "$UNINSTALL" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
echo "[卸载] 停止服务并清理规则..."
systemctl disable --now proxy-health.timer >/dev/null 2>&1 || true
systemctl disable --now wsl-redsocks-iptables.service >/dev/null 2>&1 || true
systemctl disable --now redsocks.service >/dev/null 2>&1 || true
systemctl disable --now wsl-mtu1400.service >/dev/null 2>&1 || true

/usr/local/bin/proxyctl flush-iptables || true

echo "[卸载] 删除文件..."
rm -f /etc/systemd/system/proxy-health.service /etc/systemd/system/proxy-health.timer
rm -f /etc/systemd/system/redsocks.service
rm -f /etc/systemd/system/wsl-redsocks-iptables.service
rm -f /etc/systemd/system/wsl-mtu1400.service
systemctl daemon-reload || true

rm -f /usr/local/bin/proxyctl
rm -f /usr/local/bin/proxy-healthcheck.sh
rm -f /etc/redsocks.conf
rm -f /var/log/redsocks.log
rm -f /etc/profile.d/proxyctl-aliases.sh
# 不删除 redsocks 包，以免影响其他软件；如需彻底移除自行执行：
#   sudo apt-get purge -y redsocks
#   sudo apt-get autoremove -y

echo "[卸载] 完成。建议关闭并重新打开终端以清理别名。"
EOF
  chmod +x "$UNINSTALL"
  ok "卸载脚本已创建：$UNINSTALL"
}

enable_systemd_or_cron(){
  # 有些 WSL 未开启 systemd，这里尝试优先启用 systemd 单元；失败则安装 root 的 @reboot 任务作为兜底
  info "启用服务（或安装开机自启兜底任务）..."
  if systemctl --version >/dev/null 2>&1 && systemctl is-system-running >/dev/null 2>&1; then
    systemctl enable --now redsocks.service || true
    systemctl enable --now wsl-redsocks-iptables.service || true
    systemctl enable --now wsl-mtu1400.service || true
    systemctl enable --now proxy-health.timer || true
    ok "已启用 systemd 服务。"
  else
    warn "检测到 systemd 未启用，将使用 root crontab @reboot 作为兜底。"
    # 写入开机启动：MTU + 启动代理
    (crontab -l 2>/dev/null; echo '@reboot /sbin/ip link set dev eth0 mtu 1400; /usr/local/bin/proxyctl start') | crontab -
    ok "已写入 root 的 @reboot 任务。"
  fi
}

test_with_upstream(){
  local type="$1" ip="$2" port="$3"
  info "直接用上游代理测试连通性（不走透明转发）..."
  # 优先 SOCKS5，再 HTTP
  for url in "${HEALTH_URLS[@]}"; do
    if [[ "$type" == "socks5" ]]; then
      if curl -s --max-time 10 --socks5-hostname "${ip}:${port}" "$url" >/dev/null; then
        ok "SOCKS5 直连测试成功：$url"
        return 0
      fi
    else
      if curl -s --max-time 10 --proxy "http://${ip}:${port}" "$url" >/dev/null; then
        ok "HTTP CONNECT 直连测试成功：$url"
        return 0
      fi
    fi
  done
  warn "上游直连测试失败，但仍尝试部署（某些代理限制 CONNECT 测试）。"
  return 0
}

main(){
  require_root
  install_deps
  ensure_user_group

  WIN_IP=$(detect_win_ip)
  info "检测到 Windows 主机 IP：${WIN_IP}"

  check_port_open "$WIN_IP" "$WIN_PROXY_PORT"
  PROXY_TYPE=$(detect_proxy_type "$WIN_IP" "$WIN_PROXY_PORT")

  write_redsocks_conf "$WIN_IP" "$WIN_PROXY_PORT" "$PROXY_TYPE"
  write_proxyctl
  write_healthcheck
  write_systemd_units
  write_aliases
  write_uninstall

  enable_systemd_or_cron

  # 启动一次，并测试透明代理是否可用
  info "启动透明代理..."
  "$PROXYCTL" restart

  test_with_upstream "$PROXY_TYPE" "$WIN_IP" "$WIN_PROXY_PORT"
  info "通过透明代理测试外网连通性（curl 直连，无需手动设代理）..."
  if "$PROXYCTL" test; then
    ok "部署完成！现在 WSL2 的 TCP 流量会自动通过 Windows 代理。"
    echo
    echo "快捷命令：proxy-on / proxy-off / proxy-status / proxy-test"
    echo "中文命令：代理开 / 代理关 / 状态 / 测试（重新打开终端生效）"
    echo
    echo "日志：sudo proxyctl logs"
  else
    warn "透明代理测试没有成功，请先查看：/var/log/redsocks.log，并运行：sudo proxyctl status"
  fi
}

main "$@"
