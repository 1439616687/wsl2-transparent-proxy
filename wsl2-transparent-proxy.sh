#!/usr/bin/env bash
# WSL2 Transparent Proxy v2.1 (redsocks + iptables) One-Key Installer
# Focus: stable & easy
set -Eeuo pipefail

#=============================#
#          常量/默认值         #
#=============================#
REDSOCKS_PORT=${REDSOCKS_PORT:-31338}
WIN_PROXY_PORT=${WIN_PROXY_PORT:-2080}
REDSOCKS_CONF="/etc/redsocks.conf"
REDSOCKS_LOG="/var/log/redsocks.log"
REDSOCKS_USER="redsocks"
REDSOCKS_GROUP="redsocks"
CHAIN_NAME="REDSOCKS"
MTU_VALUE=${MTU_VALUE:-1400}
SERVICE_REDSOCKS="/etc/systemd/system/redsocks.service"
SERVICE_IPTABLES="/etc/systemd/system/wsl-redsocks-iptables.service"
SERVICE_MTU="/etc/systemd/system/wsl-mtu1400.service"
SERVICE_HEALTH="/etc/systemd/system/proxy-health.service"
TIMER_HEALTH="/etc/systemd/system/proxy-health.timer"
PROXYCTL="/usr/local/bin/proxyctl"
HEALTHCHECK="/usr/local/bin/proxy-healthcheck.sh"
HEALTH_DAEMON="/usr/local/bin/proxy-health-daemon"
ALIAS_FILE="/etc/profile.d/proxyctl-aliases.sh"
UNINSTALL="/usr/local/bin/proxyctl-uninstall.sh"
WSL_CONF="/etc/wsl.conf"

#=============================#
#           输出样式           #
#=============================#
C_RESET="\033[0m"; C_BLUE="\033[1;34m"; C_GREEN="\033[1;32m"; C_YELLOW="\033[1;33m"; C_RED="\033[1;31m"
info(){ echo -e "${C_BLUE}[信息]${C_RESET} $*"; }
ok(){ echo -e "${C_GREEN}[完成]${C_RESET} $*"; }
warn(){ echo -e "${C_YELLOW}[警告]${C_RESET} $*"; }
err(){ echo -e "${C_RED}[错误]${C_RESET} $*" >&2; }
trap 'err "执行过程中出现错误。请查看上方输出定位问题。"' ERR

require_root(){ [[ $EUID -eq 0 ]] || { err "请用 root 运行：sudo $0"; exit 1; }; }
has_systemd(){ [[ -d /run/systemd/system ]] && [[ "$(ps -p 1 -o comm= 2>/dev/null || true)" == "systemd" ]]; }
default_iface(){ ip route | awk '/^default/ {print $5; exit}'; }

#=============================#
#        安装/账号准备         #
#=============================#
install_deps(){
  info "安装依赖（redsocks、iptables、curl、nc）..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y redsocks iptables iproute2 curl netcat-openbsd ca-certificates procps
  ok "依赖安装完成。"
}
ensure_user_group(){
  id -u "$REDSOCKS_USER" >/dev/null 2>&1 || adduser --system --no-create-home --group "$REDSOCKS_USER"
}

#=============================#
#        网络/代理探测         #
#=============================#
detect_win_ip(){
  local gw
  gw=$(ip route | awk '/^default via / {print $3; exit}')
  [[ -z "${gw:-}" ]] && gw=$(awk '/^nameserver /{print $2; exit}' /etc/resolv.conf || true)
  [[ -n "${gw:-}" ]] || { err "无法获取 Windows 主机 IP（默认网关）。"; exit 1; }
  echo "$gw"
}
check_port_open(){ timeout 3 bash -c "echo | nc -w2 $1 $2" >/dev/null 2>&1 || { err "无法连接 $1:$2，请检查 Windows 代理 Allow LAN/端口。"; exit 1; }; }

# ！！！关键修正：日志走 stderr，stdout 只输出类型（socks5/http-connect）
detect_proxy_type(){
  local host="$1" port="$2"
  info "识别 $host:$port 代理类型..." >&2
  local resp a b
  resp=$(printf '\x05\x01\x00' | nc -w2 "$host" "$port" | head -c2 | od -An -t u1)
  set -- $resp || true; a="${1:-}"; b="${2:-}"
  if [[ "$a" == "5" && ( "$b" == "0" || "$b" == "2" ) ]]; then
    ok "识别为 SOCKS5。" >&2
    echo "socks5"; return
  fi
  if printf 'CONNECT www.example.com:443 HTTP/1.1\r\nHost: www.example.com:443\r\n\r\n' \
      | nc -w3 "$host" "$port" | head -n1 | grep -Eq 'HTTP/1\.[01] (200|407|302|301)'; then
    ok "识别为 HTTP CONNECT。" >&2
    echo "http-connect"; return
  fi
  warn "无法明确识别，默认用 SOCKS5。" >&2
  echo "socks5"
}
sanitize_type(){
  case "$1" in
    socks5|http-connect) echo "$1" ;;
    *) echo "socks5" ;;
  esac
}

#=============================#
#        写入配置与服务        #
#=============================#
write_redsocks_conf(){
  local proxy_ip="$1" proxy_port="$2" proxy_type="$3"
  info "生成 $REDSOCKS_CONF（上游 $proxy_ip:$proxy_port，类型 $proxy_type）..."
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
  timeout = 10;
}
EOF
  touch "$REDSOCKS_LOG"
  chown "$REDSOCKS_USER:$REDSOCKS_GROUP" "$REDSOCKS_LOG" || true
  ok "redsocks 配置已写入。"
}

write_systemd_units(){
  info "写入 systemd 单元..."
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
  local ifc; ifc="$(default_iface)"; [[ -z "$ifc" ]] && ifc="eth0"
  cat > "$SERVICE_MTU" <<EOF
[Unit]
Description=Set MTU ${MTU_VALUE} on ${ifc} (WSL2)
After=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/ip link set dev ${ifc} mtu ${MTU_VALUE}
[Install]
WantedBy=multi-user.target
EOF
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
  ok "systemd 单元写入完成。"
}

write_proxyctl(){
  info "安装管理命令 $PROXYCTL ..."
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
has_systemd(){ [[ -d /run/systemd/system ]] && [[ "$(ps -p 1 -o comm= 2>/dev/null || true)" == "systemd" ]]; }
get_win_ip(){ ip route | awk '/^default via / {print $3; exit}'; }
get_iface(){ ip route | awk '/^default/ {print $5; exit}'; }
ipt(){ iptables "$@"; }
rule_exists(){ iptables "$@" -C >/dev/null 2>&1; }
ensure_chain(){ ipt -t nat -S | grep -q "^-N ${CHAIN_NAME}$" || ipt -t nat -N ${CHAIN_NAME}; ipt -t nat -F ${CHAIN_NAME}; }
apply_iptables(){
  i "应用 iptables 规则..."
  ensure_chain
  WIN_IP=$(get_win_ip); [[ -n "${WIN_IP:-}" ]] || { e "无法获取 Windows IP"; exit 1; }
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
  RED_UID=$(id -u ${REDSOCKS_USER})
  rule_exists -t nat OUTPUT -p tcp -m owner --uid-owner ${RED_UID} -j RETURN || ipt -t nat -A OUTPUT -p tcp -m owner --uid-owner ${RED_UID} -j RETURN
  rule_exists -t nat OUTPUT -p tcp -o lo -j RETURN || ipt -t nat -A OUTPUT -p tcp -o lo -j RETURN
  rule_exists -t nat OUTPUT -p tcp -d 127.0.0.0/8 -j RETURN || ipt -t nat -A OUTPUT -p tcp -d 127.0.0.0/8 -j RETURN
  rule_exists -t nat OUTPUT -p tcp -j ${CHAIN_NAME} || ipt -t nat -A OUTPUT -p tcp -j ${CHAIN_NAME}
  o "iptables 规则已应用。"
}
flush_iptables(){
  i "清理 iptables 规则..."
  RED_UID=$(id -u ${REDSOCKS_USER} 2>/dev/null || echo 0)
  ipt -t nat -D OUTPUT -p tcp -m owner --uid-owner ${RED_UID} -j RETURN >/dev/null 2>&1 || true
  ipt -t nat -D OUTPUT -p tcp -o lo -j RETURN >/dev/null 2>&1 || true
  ipt -t nat -D OUTPUT -p tcp -d 127.0.0.0/8 -j RETURN >/dev/null 2>&1 || true
  ipt -t nat -D OUTPUT -p tcp -j ${CHAIN_NAME} >/dev/null 2>&1 || true
  ipt -t nat -F ${CHAIN_NAME} >/dev/null 2>&1 || true
  ipt -t nat -X ${CHAIN_NAME} >/dev/null 2>&1 || true
  o "iptables 规则已清理。"
}
start(){
  if has_systemd; then
    systemctl enable --now redsocks.service >/dev/null 2>&1 || true
    systemctl enable --now wsl-redsocks-iptables.service >/dev/null 2>&1 || true
    systemctl enable --now wsl-mtu1400.service >/dev/null 2>&1 || true
    systemctl enable --now proxy-health.timer >/dev/null 2>&1 || true
  else
    pidof redsocks >/dev/null 2>&1 || /usr/sbin/redsocks -c "$REDSOCKS_CONF" || true
    apply_iptables
    IFACE=$(get_iface); [[ -z "$IFACE" ]] && IFACE="eth0"; ip link set dev "$IFACE" mtu 1400 || true
  fi
  o "透明代理已启动。"
}
stop(){
  if has_systemd; then
    systemctl stop proxy-health.timer >/dev/null 2>&1 || true
    systemctl stop wsl-redsocks-iptables.service >/dev/null 2>&1 || true
    systemctl stop redsocks.service >/dev/null 2>&1 || true
  else
    pkill -x redsocks >/dev/null 2>&1 || true
  fi
  flush_iptables
  o "透明代理已停止。"
}
restart(){ stop || true; start; }
status(){
  echo "=== redsocks 进程 ==="
  if pidof redsocks >/dev/null 2>&1; then echo "运行中 (PID: $(pidof redsocks))"; else echo "未运行或由 systemd 管理"; fi
  echo; has_systemd && { echo "=== systemd: redsocks ==="; systemctl --no-pager -l status redsocks.service || true; echo; echo "=== systemd: health.timer ==="; systemctl --no-pager -l status proxy-health.timer || true; echo; }
  echo "=== iptables REDSOCKS 链 ==="; iptables -t nat -S ${CHAIN_NAME} || echo "(未创建链)"
}
test_conn(){
  for u in "https://cp.cloudflare.com/generate_204" "https://www.microsoft.com" "https://detectportal.firefox.com/success.txt"; do
    echo "--- 测试: $u"
    if curl -I --max-time 10 -sS "$u" | head -n1; then o "成功访问：$u"; exit 0; fi
  done
  e "测试未通过，请查看日志：$REDSOCKS_LOG"; exit 1
}
logs(){ tail -n 200 -f "$REDSOCKS_LOG"; }
set_type(){
  local t="${1:-}"; [[ "$t" == "socks5" || "$t" == "http-connect" ]] || { e "用法：$0 set-type socks5|http-connect"; exit 1; }
  sed -i "s/^  type = .*/  type = ${t};/" "$REDSOCKS_CONF"; o "已切换为 ${t}，重启生效。"
}
usage(){ cat <<USAGE
proxyctl:
  start/stop/restart/status/test/logs
  apply-iptables / flush-iptables
  set-type socks5|http-connect
USAGE
}
case "${1:-}" in
  start) start;; stop) stop;; restart) restart;; status) status;; test) test_conn;; logs) logs;;
  apply-iptables) apply_iptables;; flush-iptables) flush_iptables;; set-type) set_type "${2:-}";;
  *) usage;;
esac
EOF
  chmod +x "$PROXYCTL"
  ok "管理命令已安装：$PROXYCTL"
}

write_health_tools(){
  info "写入健康检查/守护 ..."
  cat > "$HEALTHCHECK" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
URLS=("https://cp.cloudflare.com/generate_204" "https://www.microsoft.com" "https://detectportal.firefox.com/success.txt")
log(){ logger -t proxy-health "$*"; echo "$(date '+%F %T') proxy-health: $*"; }
ok=0
for u in "${URLS[@]}"; do if curl -s --max-time 8 "$u" >/dev/null; then ok=1; break; fi; done
if [[ $ok -eq 1 ]]; then
  log "OK"
  UPTIME=$(awk '{print int($1)}' /proc/uptime)
  if (( UPTIME > 86400 )); then
    if [[ -d /run/systemd/system ]] && [[ "$(ps -p 1 -o comm= 2>/dev/null || true)" == "systemd" ]]; then
      systemctl restart redsocks.service || true
    else
      pkill -x redsocks >/dev/null 2>&1 || true
      /usr/sbin/redsocks -c /etc/redsocks.conf || true
    fi
    log "redsocks restarted for pool refresh"
  fi
  exit 0
else
  log "failed, self-heal.."
  if [[ -d /run/systemd/system ]] && [[ "$(ps -p 1 -o comm= 2>/dev/null || true)" == "systemd" ]]; then
    systemctl restart redsocks.service || true
    /usr/local/bin/proxyctl apply-iptables || true
  else
    pkill -x redsocks >/dev/null 2>&1 || true
    /usr/sbin/redsocks -c /etc/redsocks.conf || true
    /usr/local/bin/proxyctl apply-iptables || true
  fi
  sleep 2
  for u in "${URLS[@]}"; do if curl -s --max-time 8 "$u" >/dev/null; then log "recovered"; exit 0; fi; done
  log "still failing"; exit 1
fi
EOF
  chmod +x "$HEALTHCHECK"

  cat > "$HEALTH_DAEMON" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
while true; do /usr/local/bin/proxy-healthcheck.sh || true; sleep 300; done
EOF
  chmod +x "$HEALTH_DAEMON"
  ok "健康检查脚本已创建。"
}

write_aliases(){
  info "写入别名 ..."
  cat > "$ALIAS_FILE" <<'EOF'
alias proxy-on='sudo proxyctl start'
alias proxy-off='sudo proxyctl stop'
alias proxy-status='sudo proxyctl status'
alias proxy-test='sudo proxyctl test'
alias 代理开='sudo proxyctl start'
alias 代理关='sudo proxyctl stop'
alias 状态='sudo proxyctl status'
alias 测试='sudo proxyctl test'
EOF
  ok "别名已写入（新开终端生效）。"
}

write_uninstall(){
  info "写入卸载脚本 ..."
  cat > "$UNINSTALL" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
echo "[卸载] 停止服务/守护并清理规则..."
if [[ -d /run/systemd/system ]] && [[ "$(ps -p 1 -o comm= 2>/dev/null || true)" == "systemd" ]]; then
  systemctl disable --now proxy-health.timer >/dev/null 2>&1 || true
  systemctl disable --now wsl-redsocks-iptables.service >/dev/null 2>&1 || true
  systemctl disable --now redsocks.service >/dev/null 2>&1 || true
  systemctl disable --now wsl-mtu1400.service >/dev/null 2>&1 || true
else
  pkill -f /usr/local/bin/proxy-health-daemon >/dev/null 2>&1 || true
  pkill -x redsocks >/dev/null 2>&1 || true
fi
/usr/local/bin/proxyctl flush-iptables || true
rm -f /etc/systemd/system/proxy-health.service /etc/systemd/system/proxy-health.timer
rm -f /etc/systemd/system/redsocks.service /etc/systemd/system/wsl-redsocks-iptables.service /etc/systemd/system/wsl-mtu1400.service
systemctl daemon-reload >/dev/null 2>&1 || true
rm -f /usr/local/bin/proxyctl /usr/local/bin/proxy-healthcheck.sh /usr/local/bin/proxy-health-daemon
rm -f /etc/redsocks.conf /var/log/redsocks.log /etc/profile.d/proxyctl-aliases.sh
echo "[卸载] 完成。"
EOF
  chmod +x "$UNINSTALL"
  ok "卸载脚本已创建：$UNINSTALL"
}

setup_autostart(){
  if has_systemd; then
    info "检测到 systemd，注册服务并启用..."
    systemctl daemon-reload
    systemctl enable --now redsocks.service wsl-redsocks-iptables.service wsl-mtu1400.service proxy-health.timer || true
    ok "systemd 服务已启用。"
  else
    info "systemd 未启用，使用 wsl.conf 启动 + 守护..."
    local ifc; ifc="$(default_iface)"; [[ -z "$ifc" ]] && ifc="eth0"
    tee "$WSL_CONF" >/dev/null <<EOF
[boot]
command = /bin/sh -lc 'ip link set dev ${ifc} mtu ${MTU_VALUE}; /usr/local/bin/proxyctl start; nohup /usr/local/bin/proxy-health-daemon >/dev/null 2>&1 &'
EOF
    ok "已写入 $WSL_CONF ；执行一次  wsl --shutdown  后生效。"
  fi
}

test_with_upstream(){
  local type="$1" ip="$2" port="$3"
  info "直接使用上游代理测试（不走透明）..."
  for url in "https://cp.cloudflare.com/generate_204" "https://www.microsoft.com" "https://detectportal.firefox.com/success.txt"; do
    if [[ "$type" == "socks5" ]]; then
      curl -s --max-time 10 --socks5-hostname "${ip}:${port}" "$url" >/dev/null && { ok "SOCKS5 直连成功：$url"; return 0; }
    else
      curl -s --max-time 10 --proxy "http://${ip}:${port}" "$url" >/dev/null && { ok "HTTP CONNECT 直连成功：$url"; return 0; }
    fi
  done
  warn "上游直连未通过（不一定是问题），继续用透明测试确认。"
}

#=============================#
#            主流程            #
#=============================#
main(){
  require_root
  install_deps
  ensure_user_group

  WIN_IP=$(detect_win_ip); info "检测到 Windows 主机 IP：$WIN_IP"
  check_port_open "$WIN_IP" "$WIN_PROXY_PORT"
  RAW_TYPE=$(detect_proxy_type "$WIN_IP" "$WIN_PROXY_PORT")
  PROXY_TYPE=$(sanitize_type "$RAW_TYPE")

  write_redsocks_conf "$WIN_IP" "$WIN_PROXY_PORT" "$PROXY_TYPE"
  write_proxyctl
  write_health_tools
  write_aliases
  write_uninstall
  has_systemd && write_systemd_units || warn "当前 WSL 未启用 systemd，将使用 wsl.conf 自启动与守护。"
  setup_autostart

  info "立即启动透明代理..."
  "$PROXYCTL" restart

  test_with_upstream "$PROXY_TYPE" "$WIN_IP" "$WIN_PROXY_PORT"
  info "通过透明代理测试（无需手动设代理）..."
  if "$PROXYCTL" test; then
    ok "部署成功！WSL2 的 TCP 流量已透明走 Windows 代理。"
    echo "命令：proxy-on / proxy-off / proxy-status / proxy-test ；中文：代理开/代理关/状态/测试"
    echo "日志：sudo proxyctl logs"
    has_systemd || echo "提示：要让自启动生效，请在 Windows PowerShell 执行： wsl --shutdown  ，再进入 WSL。"
  else
    warn "透明代理测试未通过，请先看日志：/var/log/redsocks.log ，并执行：sudo proxyctl status"
  fi
}
main "$@"
