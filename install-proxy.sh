#!/bin/bash
# install-proxy.sh — AI-agent egress through the hub VPS over SSH.
# Hub side: tinyproxy on 127.0.0.1:$PORT. Mac side: autossh port-forward as a user
# LaunchAgent; a PAC file served from localhost makes the system send only the
# AI hosts (client/ai-egress.pac) through it, so browsers and desktop apps are
# covered; CLIs that ignore system proxy get env: Claude (settings.json), Codex
# (shell wrapper). No routes, no packet filter, no root on the Mac: works
# wherever `ssh $HUB` works.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HUB="${HUB:-vpn}"
PORT="${PORT:-8888}"
PAC_PORT="${PAC_PORT:-8889}"
LABEL="org.egress-tunnel.proxy"
PAC_LABEL="org.egress-tunnel.pac"
PAC_DIR="$HOME/.ai-egress-proxy"
# Hosts that must NOT go through the hub (reached directly on the LAN/overlay).
# Add your own LAN or private-network addresses here.
NO_PROXY_LIST="${NO_PROXY_LIST:-localhost,127.0.0.1,.local}"

echo "== 1. hub ($HUB): tinyproxy on 127.0.0.1:$PORT =="
ssh "$HUB" 'export DEBIAN_FRONTEND=noninteractive; command -v tinyproxy >/dev/null || apt-get install -y -qq tinyproxy >/dev/null'
# tinyproxy.conf ships with Port 8888; rewrite it so a non-default $PORT is not
# silently ignored (the hub would listen on 8888 while the forward expects $PORT).
sed -e "s|^Port .*|Port $PORT|" "$DIR/server/tinyproxy.conf" \
  | ssh "$HUB" 'cat > /etc/tinyproxy/tinyproxy.conf'
ssh "$HUB" "systemctl enable -q tinyproxy; systemctl restart tinyproxy; sleep 1; ss -ltn | grep -q '127.0.0.1:$PORT' && echo listening"

echo "== 2. mac: autossh LaunchAgent $LABEL =="
AUTOSSH="$(command -v autossh || true)"
[ -n "$AUTOSSH" ] || { echo "autossh not found: brew install autossh"; exit 1; }
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
sed -e "s|__AUTOSSH__|$AUTOSSH|g" -e "s|__HUB__|$HUB|g" -e "s|__PORT__|$PORT|g" -e "s|__HOME__|$HOME|g" \
  "$DIR/launchd/$LABEL.plist.template" > "$PLIST"
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"
for _ in $(seq 1 20); do
  curl -s -o /dev/null -x "http://127.0.0.1:$PORT" --max-time 5 https://api.anthropic.com/ && break
  sleep 1
done
curl -s -o /dev/null -x "http://127.0.0.1:$PORT" -w "anthropic via hub: %{http_code} %{time_total}s\n" --max-time 10 https://api.anthropic.com/v1/models

echo "== 3. system: PAC on 127.0.0.1:$PAC_PORT -> only AI hosts use the proxy =="
mkdir -p "$PAC_DIR"
sed -e "s|127.0.0.1:8888|127.0.0.1:$PORT|g" "$DIR/client/ai-egress.pac" > "$PAC_DIR/ai-egress.pac"
PAC_PLIST="$HOME/Library/LaunchAgents/$PAC_LABEL.plist"
sed -e "s|__PAC_DIR__|$PAC_DIR|g" -e "s|__PAC_PORT__|$PAC_PORT|g" -e "s|__HOME__|$HOME|g" \
  "$DIR/launchd/$PAC_LABEL.plist.template" > "$PAC_PLIST"
launchctl bootout "gui/$(id -u)/$PAC_LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PAC_PLIST"
PAC_URL="http://127.0.0.1:$PAC_PORT/ai-egress.pac"
for _ in $(seq 1 10); do curl -sf -o /dev/null "$PAC_URL" && break; sleep 1; done
# Hard-fail rather than point every network service at a PAC URL that 404s:
# macOS then behaves inconsistently per app with no visible error anywhere.
curl -sf -o /dev/null "$PAC_URL" \
  || { echo "PAC server never came up on $PAC_URL -- not enabling system auto-proxy"; exit 1; }
# Every service except the VPN pseudo-interfaces, so Wi-Fi, cable and tethering all behave the same.
networksetup -listallnetworkservices | tail -n +2 | grep -vE '^(\*|Tailscale|VPN)' | while read -r svc; do
  networksetup -setautoproxyurl "$svc" "$PAC_URL"
  networksetup -setautoproxystate "$svc" on
  echo "  $svc -> $PAC_URL"
done

echo "== 4. claude: proxy env in ~/.claude/settings.json =="
python3 - "$PORT" "$NO_PROXY_LIST" <<'PY'
import json, pathlib, sys
port, no_proxy = sys.argv[1], sys.argv[2]
p = pathlib.Path.home() / ".claude/settings.json"
p.parent.mkdir(parents=True, exist_ok=True)  # Codex-only machine has no ~/.claude
d = json.loads(p.read_text()) if p.exists() else {}
env = d.setdefault("env", {})
env["HTTPS_PROXY"] = env["HTTP_PROXY"] = f"http://127.0.0.1:{port}"
env["NO_PROXY"] = no_proxy
p.write_text(json.dumps(d, indent=2, ensure_ascii=False) + "\n")
print("ok", p)
PY

echo "== 5. codex: takes the proxy only from the environment -> shell wrapper =="
RC="$HOME/.zshrc"
MARK="# ai-egress-proxy (egress-tunnel/install-proxy.sh)"
if ! grep -qF "$MARK" "$RC" 2>/dev/null; then
  cat >> "$RC" <<EOF

$MARK
codex() { HTTPS_PROXY=http://127.0.0.1:$PORT HTTP_PROXY=http://127.0.0.1:$PORT NO_PROXY="$NO_PROXY_LIST" command codex "\$@"; }
EOF
  echo "codex() added to $RC — open a new shell"
else
  echo "codex() already in $RC"
fi

echo "== done: launchctl print gui/$(id -u)/$LABEL | grep state; scutil --proxy; tail ~/Library/Logs/ai-egress-proxy.err =="
