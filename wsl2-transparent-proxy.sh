#!/usr/bin/env bash
# WSL2 Transparent Proxy v2 (redsocks + iptables) One-Key Installer
# Author: chatGPT
# Target: Ubuntu (WSL2) 20.04/22.04/24.04
# Features:
# - 自动识别 Windows IP、自动识别上游代理类型（SOCKS5/HTTP CONNECT）
# - redsocks + iptables 透明代理（TCP 全量转发）
# - 内网地址排除 + 回环/自身排除，避免循环
# - 健康检查与自修复（systemd.timer 或 wsl.conf 后台守护）
# - 固定 MTU=1400，减少 HTTPS/TLS 相关问题
# - 中英文管理命令、开机自启（systemd 或 wsl.conf）
# - 一键卸载

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
#          彩色输出工具        #
#=============================#
C_RESET="\033[0m"; C_BLUE="\033[1;34m"; C_GREEN="\033[1;32m"; C_YELLOW="\033[1;33m"; C_RED="\033[1;31m"
info(){ echo -e "${C_BLUE}[信息]${C_RESET} $*"; }
ok(){ echo -e "${C_GREEN}[完成]${C_RESET} $*"; }
warn(){ echo -e "${C_YELLOW}[警告]${C_RESET} $*"; }
err(){ echo -e "${C_RED}[错误]${C_RESET} $*" >&2; }

trap 'err "执行过程中出现错误。请向上查看具体报错信息。"' ERR

#=============================#
#         工具/环境函数        #
#=============================#
require_root(){
  if [[ ${EUID} -ne 0 ]]; then
    err "请用 root 权限运行：sudo $0"
    exit 1
  fi
}

has_systemd(){
  # WSL 开启 systemd 时 /run/systemd/system 存在，且 PID 1 是 systemd
  if [[ -d /run/systemd/system ]] && [[ "$(ps -p 1 -o comm= 2>/dev/null || true)" == "systemd" ]]; then
    return 0
  else
    return 1
  fi
}

default_iface(){
  ip route | awk '/^default/ {print $5; exit}'
}

#=============================#
#        依赖安装/账号组       #
#=============================#
install_deps(){
  info "安装依赖（redsocks、iptables、curl、netcat 等）..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y redsocks iptables iproute2 curl netcat-openbsd ca-certificates procps
  ok "依赖安装完成。"
}

ensure_user_group(){
  if ! id -u "$REDSOCKS_USER" >/dev/null 2>&1; then
    info "创建系统用户 ${REDSOCKS_USER}..."
    adduser --system --no-create-home --group "$REDSOCKS_USER"
  fi
}

#=============================#
#        网络/代理探测         #
#=============================#
detect_win_ip(){
  local gw
  gw=$(ip route | awk '/^default via / {print $3; exit}')
  if [[ -z "${gw:-}" ]]; then
    gw=$(awk '/^nameserver /{print $2; exit}' /etc/resolv.conf || true)
  fi
  if [[ -z "${gw:-}" ]]; then
    err "无法自动获取 Windows 主机 IP（默认网关）。请检查网络或重启 WSL。"
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
  info "尝试识别 ${host}:${port} 是 SOCKS5 还是 HTTP CONNECT..."
  # 尝试 SOCKS5 握手
  local resp a b
  resp=$(printf '\x05\x01\x00' | nc -w2 "$host" "$port" | head -c2 | od -An -t u1)
  set -- $resp || true
  a="${1:-}"; b="${2:-}"
  if [[ "$a" == "5" && ( "$b" == "0" || "$b" == "2" ) ]]; then
    ok "识别为 SOCKS5。"
    echo "socks5"
    return
  fi
  # 尝试 HTTP CONNECT
  if printf 'CONNECT www.example.com:443 HTTP/1.1\r\nHost: www.example.com:443\r\n\r\n' \
      | nc -w3 "$host" "$port" | head -n1 | grep -Eq 'HTTP/1\.[01] (200|407|302|301)'; then
    ok "识别为 HTTP CONNECT。"
    echo "http-connect"
    return
  fi
  warn "无法明确识别类型，默认使用 SOCKS5（sing-box/clash 常用）。"
  echo "socks5"
}

#=============================#
#        写入配置与服务        #
#=============================#
write_redsocks_conf(){
  local proxy_ip="$1" proxy_port="$2" proxy_type="$3"
  info "生成 ${REDSOCKS_CONF}（上游 ${proxy_ip}:${proxy_port}，类型 ${proxy_type}）..."
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
  // 超时设置，减少僵尸连接
  timeout = 10;
}
EOF
  touch "$REDSOCKS_LOG"
  chown "$REDSOCKS_USER:$REDSOCKS_GROUP" "$REDSOCKS_LOG" || true
  ok "已生成 redsocks 配置。"
}

write_systemd_units(){
  info "写入 systemd 单元..."
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
  local ifc; ifc="$(default_iface)"; if [[ -z "${ifc}" ]]; then ifc="eth0"; fi
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

  ok "systemd 单元写入完成。"
}

write_proxyctl(){
  info "安装管理命令 ${PROXYCTL} ..."
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

has_systemd(){
  [[ -d /run/systemd/system ]] && [[ "$(ps -p 1 -o comm= 2>/dev/null || true)" == "systemd" ]]
}

get_win_ip(){ ip route | awk '/^default via / {print $3; exit}'; }
get_iface(){ ip route | awk '/^default/ {print $5; exit}'; }

ipt(){ iptables "$@"; }

rule_exists(){ iptables "$@" -C >/dev/null 2>&1; }

ensure_chain(){
  if ! ipt -t nat -S | grep -q "^-N ${CHAIN_NAME}$"; then
    ipt -t nat -N ${CHAIN_NAME}
  fi
  ipt -t nat -F ${CHAIN_NAME}
}

apply_iptables(){
  i "应用 iptables 透明代理规则..."
  ensure_chain
  WIN_IP=$(get_win_ip)
  if [[ -z "${WIN_IP:-}" ]]; then e "无法获取 Windows IP"; exit 1; fi

  # REDSOCKS 自定义链：排除保留/内网/本机/Windows，再重定向 TCP 到 redsocks
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

  # OUTPUT 链：仅本机发起的 TCP，排除 redsocks 用户与 lo，再跳转到 REDSOCKS
  RED_UID=$(id -u ${REDSOCKS_USER})
  rule_exists -t nat OUTPUT -p tcp -m owner --uid-owner ${RED_UID} -j RETURN || ipt -t nat -A OUTPUT -p tcp -m owner --uid-owner ${RED_UID} -j RETURN
  rule_exists -t nat OUTPUT -p tcp -o lo -j RETURN || ipt -t nat -A OUTPUT -p tcp -o lo -j RETURN
  rule_exists -t nat OUTPUT -p tcp -d 127.0.0.0/8 -j RETURN || ipt -t nat -A OUTPUT -p tcp -d 127.0.0.0/8 -j RETURN
  rule_exists -t nat OUTPUT -p tcp -j ${CHAIN_NAME} || ipt -t nat -A OUTPUT -p tcp -j ${CHAIN_NAME}

  o "iptables 规则已应用。"
}

flush_iptables(){
  i "清理 iptables 规则..."
  # 删除 OUTPUT 链上的跳转/RETURN（若存在）
  RED_UID=$(id -u ${REDSOCKS_USER} 2>/dev/null || echo 0)
  ipt -t nat -D OUTPUT -p tcp -m owner --uid-owner ${RED_UID} -j RETURN >/dev/null 2>&1 || true
  ipt -t nat -D OUTPUT -p tcp -o lo -j RETURN >/dev/null 2>&1 || true
  ipt -t nat -D OUTPUT -p tcp -d 127.0.0.0/8 -j RETURN >/dev/null 2>&1 || true
  ipt -t nat -D OUTPUT -p tcp -j ${CHAIN_NAME} >/dev/null 2>&1 || true
  # 删除自定义链
  if ipt -t nat -S | grep -q "^-N ${CHAIN_NAME}$"; then
    ipt -t nat -F ${CHAIN_NAME} || true
    ipt -t nat -X ${CHAIN_NAME} || true
  fi
  o "iptables 规则已清理。"
}

start(){
  if has_systemd; then
    systemctl enable --now redsocks.service >/dev/null 2>&1 || true
    systemctl enable --now wsl-redsocks-iptables.service >/dev/null 2>&1 || true
    systemctl enable --now wsl-mtu1400.service >/dev/null 2>&1 || true
    systemctl enable --now proxy-health.timer >/dev/null 2>&1 || true
  else
    # 非 systemd：直接运行 redsocks（daemon=on 会守护化），并应用规则
    if ! pidof redsocks >/dev/null 2>&1; then
      /usr/sbin/redsocks -c "$REDSOCKS_CONF" || true
      sleep 1
    fi
    apply_iptables
    # 设置 MTU
    IFACE=$(get_iface); [[ -z "$IFACE" ]] && IFACE="eth0"
    ip link set dev "$IFACE" mtu 1400 || true
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
  if pidof redsocks >/dev/null 2>&1; then
    echo "运行中 (PID: $(pidof redsocks))"
  else
    echo "未运行或由 systemd 管理（请看下方服务状态）"
  fi
  echo
  if has_systemd; then
    echo "=== systemd: redsocks.service ==="
    systemctl --no-pager -l status redsocks.service || true
    echo
    echo "=== systemd: proxy-health.timer ==="
    systemctl --no-pager -l status proxy-health.timer || true
    echo
  fi
  echo "=== iptables REDSOCKS 链 ==="
  iptables -t nat -S ${CHAIN_NAME} || echo "(未创建链)"
}

test_conn(){
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

logs(){ tail -n 200 -f "$REDSOCKS_LOG"; }

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
  start           启动透明代理（自动判断 systemd）
  stop            停止并清理规则
  restart         重启
  status          查看状态
  test            连通性测试
  logs            实时查看 redsocks 日志
  apply-iptables  仅应用 iptables 规则
  flush-iptables  仅清理 iptables 规则
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
  ok "管理命令已安装：$PROXYCTL"
}

write_health_tools(){
  info "写入健康检查与守护脚本 ..."
  # 一次性健康检查（被 systemd.timer 调用或守护调用）
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
  # 运行超过 1 天则刷新连接
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
  log "failed, attempting self-heal..."
  if [[ -d /run/systemd/system ]] && [[ "$(ps -p 1 -o comm= 2>/dev/null || true)" == "systemd" ]]; then
    systemctl restart redsocks.service || true
    /usr/local/bin/proxyctl apply-iptables || true
  else
    pkill -x redsocks >/dev/null 2>&1 || true
    /usr/sbin/redsocks -c /etc/redsocks.conf || true
    /usr/local/bin/proxyctl apply-iptables || true
  fi
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

  # 无 systemd 环境：后台守护（每 5 分钟执行一次健康检查）
  cat > "$HEALTH_DAEMON" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
while true; do
  /usr/local/bin/proxy-healthcheck.sh || true
  sleep 300
done
EOF
  chmod +x "$HEALTH_DAEMON"
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

echo "[卸载] 删除文件..."
rm -f /etc/systemd/system/proxy-health.service /etc/systemd/system/proxy-health.timer
rm -f /etc/systemd/system/redsocks.service
rm -f /etc/systemd/system/wsl-redsocks-iptables.service
rm -f /etc/systemd/system/wsl-mtu1400.service
systemctl daemon-reload >/dev/null 2>&1 || true

rm -f /usr/local/bin/proxyctl
rm -f /usr/local/bin/proxy-healthcheck.sh
rm -f /usr/local/bin/proxy-health-daemon
rm -f /etc/redsocks.conf
rm -f /var/log/redsocks.log
rm -f /etc/profile.d/proxyctl-aliases.sh

# 不强制卸载包，如需彻底移除：
#   sudo apt-get purge -y redsocks
#   sudo apt-get autoremove -y

echo "[卸载] 完成。建议关闭并重新打开终端以清理别名。"
EOF
  chmod +x "$UNINSTALL"
  ok "卸载脚本已创建：$UNINSTALL"
}

setup_autostart(){
  if has_systemd; then
    info "检测到 systemd 已启用，注册服务并开机自启..."
    systemctl daemon-reload
    systemctl enable --now redsocks.service || true
    systemctl enable --now wsl-redsocks-iptables.service || true
    systemctl enable --now wsl-mtu1400.service || true
    systemctl enable --now proxy-health.timer || true
    ok "systemd 服务与定时器已启用。"
  else
    info "systemd 未启用，配置 wsl.conf 自启动 + 守护健康巡检..."
    local ifc; ifc="$(default_iface)"; [[ -z "$ifc" ]] && ifc="eth0"
    tee "$WSL_CONF" >/dev/null <<EOF
[boot]
# 每次 WSL 启动自动设 MTU + 启动透明代理 + 后台健康巡检
command = /bin/sh -lc 'ip link set dev ${ifc} mtu ${MTU_VALUE}; /usr/local/bin/proxyctl start; nohup /usr/local/bin/proxy-health-daemon >/dev/null 2>&1 &'
EOF
    ok "已写入 $WSL_CONF 。请在 Windows PowerShell 执行：  wsl --shutdown  ，然后重新进入 WSL 生效。"
  fi
}

test_with_upstream(){
  local type="$1" ip="$2" port="$3"
  local urls=("https://cp.cloudflare.com/generate_204" "https://www.microsoft.com" "https://detectportal.firefox.com/success.txt")
  info "直接使用上游代理测试连通性（不走透明）..."
  for url in "${urls[@]}"; do
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
  warn "上游直连测试未通过（不一定代表异常），继续部署并通过透明测试验证。"
  return 0
}

#=============================#
#            主流程            #
#=============================#
main(){
  require_root
  install_deps
  ensure_user_group

  local WIN_IP PROXY_TYPE IFACE
  WIN_IP=$(detect_win_ip)
  info "检测到 Windows 主机 IP：${WIN_IP}"
  check_port_open "$WIN_IP" "$WIN_PROXY_PORT"
  PROXY_TYPE=$(detect_proxy_type "$WIN_IP" "$WIN_PROXY_PORT")

  write_redsocks_conf "$WIN_IP" "$WIN_PROXY_PORT" "$PROXY_TYPE"
  write_proxyctl
  write_health_tools
  write_aliases
  write_uninstall

  if has_systemd; then
    write_systemd_units
  else
    warn "当前 WSL 未启用 systemd，将使用 wsl.conf 自启动与守护。"
  fi

  setup_autostart

  info "立即启动透明代理..."
  "$PROXYCTL" restart

  test_with_upstream "$PROXY_TYPE" "$WIN_IP" "$WIN_PROXY_PORT"
  info "通过透明代理测试外网连通性（无需手动设代理）..."
  if "$PROXYCTL" test; then
    ok "部署完成！WSL2 的 TCP 流量已透明走 Windows 代理。"
    echo
    echo "快捷命令：proxy-on / proxy-off / proxy-status / proxy-test"
    echo "中文命令：代理开 / 代理关 / 状态 / 测试   （重新开终端后别名生效）"
    echo "日志：sudo proxyctl logs"
    if ! has_systemd; then
      echo
      echo "提示：要让自启动生效，请在 Windows PowerShell 执行：  wsl --shutdown  ，再重新打开 WSL。"
    fi
  else
    warn "透明代理测试未通过，请查看：/var/log/redsocks.log，并执行：sudo proxyctl status"
  fi
}

main "$@"
