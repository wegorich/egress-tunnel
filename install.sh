#!/bin/bash
# install.sh — egress for AI-agent traffic through the hub VPS. Two modes:
#   ./install.sh         wg    — WireGuard split-tunnel (default): system-wide, near-native latency
#   ./install.sh proxy         — HTTP proxy over SSH: for networks where WireGuard/UDP is throttled
# Each mode switches the other one off, so the machine is always in one known state.
# Run it from your own terminal (not from agent automation) — wg mode needs sudo
# for the root daemons and, possibly, to build the Go binary.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"
MODE="${1:-wg}"
HUB="${HUB:-vpn}"

# The LaunchDaemons run as root and need to open egress_tunnel.py and config.yaml
# themselves (not just exec the interpreter). macOS TCC blocks that when the file
# sits under a protected folder (Documents/Desktop/Downloads/...) unless the
# reading binary has Full Disk Access — which we don't want to require. So the
# runtime files are synced to a plain dot-dir under $HOME instead; this checkout
# stays the source of truth for editing.
RUNTIME_DIR="$HOME/.egress-tunnel/app"

proxy_off() {
  for l in org.egress-tunnel.proxy org.egress-tunnel.pac; do
    launchctl bootout "gui/$(id -u)/$l" 2>/dev/null || true
    # bootout only lasts the session: the plists stay in ~/Library/LaunchAgents
    # and load again at the next login, quietly putting a dead autossh forward
    # back. disable is what makes "off" survive a reboot, the way wg_off does.
    launchctl disable "gui/$(id -u)/$l" 2>/dev/null || true
  done
  # grep exits 1 when no service survives the filter (every service disabled, or
  # only VPN pseudo-services present). Under `set -o pipefail` that would abort
  # the installer right here -- after it announced success, and before the env
  # cleanup below -- leaving the CLIs pointed at a proxy that is now gone.
  { networksetup -listallnetworkservices | tail -n +2 | grep -vE '^(\*|Tailscale|VPN)' | while read -r svc; do
    networksetup -setautoproxystate "$svc" off
  done; } || true
  python3 - <<'PY'
import json, pathlib
p = pathlib.Path.home() / ".claude/settings.json"
if p.exists():
    d = json.loads(p.read_text())
    env = d.get("env", {})
    # Only rewrite when something actually goes: an unconditional write
    # reformats the user's settings file on every wg install for nothing.
    if any(k in env for k in ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY")):
        for k in ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY"):
            env.pop(k, None)
        p.write_text(json.dumps(d, indent=2, ensure_ascii=False) + "\n")
rc = pathlib.Path.home() / ".zshrc"
mark = "# ai-egress-proxy (egress-tunnel/install-proxy.sh)"
if rc.exists() and mark in rc.read_text():
    lines = rc.read_text().split("\n")
    i = lines.index(mark)
    del lines[i:i + 2]
    if i > 0 and lines[i - 1] == "":
        del lines[i - 1]
    rc.write_text("\n".join(lines))
PY
  echo "proxy mode: off (agents unloaded, system auto-proxy off, claude/codex env removed)"
}

wg_off() {
  for l in org.egress-tunnel.watchdog org.egress-tunnel.interface; do
    sudo launchctl bootout "system/$l" 2>/dev/null || true
    sudo launchctl disable "system/$l"
  done
  echo "wg mode: off (daemons unloaded and disabled)"
}

case "$MODE" in
  proxy)
    # The mirror of step 9, in the other direction. install-proxy.sh runs under
    # set -e and can die on an unreachable hub, a missing autossh, or a forward
    # that never comes up. Tearing wg down first would leave the machine in
    # NEITHER mode -- the exact failure this file exists to prevent -- so wg
    # stays up until the proxy has actually carried a request.
    "$DIR/install-proxy.sh"
    PROXY_CODE=$(curl -s -o /dev/null --max-time 10 -x "http://127.0.0.1:${PORT:-8888}" \
                   -w '%{http_code}' https://api.anthropic.com/v1/models || true)
    if [ "$PROXY_CODE" = "401" ]; then
      echo "proxy carries api.anthropic.com (HTTP 401) -- switching wg mode off"
      wg_off
    else
      echo "WARNING: the proxy did not carry api.anthropic.com (got ${PROXY_CODE:-no response})."
      echo "Leaving WireGuard mode as it is, so this machine keeps a working path."
    fi
    exit 0
    ;;
  wg) ;;
  *) echo "usage: $0 [wg|proxy]"; exit 1 ;;
esac

echo "== 1. amneziawg-go =="
if [ ! -x bin/amneziawg-go ]; then
  if ! command -v go >/dev/null 2>&1; then
    echo "Go not found. Install it: https://go.dev/dl/ (needs 1.25+) and re-run install.sh."
    exit 1
  fi
  GO_VERSION=$(go env GOVERSION | sed -e 's/^go//')
  GO_MAJOR=$(echo "$GO_VERSION" | cut -d. -f1)
  GO_MINOR=$(echo "$GO_VERSION" | cut -d. -f2)
  if ! [[ "$GO_MAJOR" =~ ^[0-9]+$ ]] || ! [[ "$GO_MINOR" =~ ^[0-9]+$ ]]; then
    echo "Couldn't parse go version from 'go env GOVERSION' output: $GO_VERSION"
    echo "(probably a devel/tip build) — install a released 1.25+ from https://go.dev/dl/ and re-run install.sh."
    exit 1
  fi
  if [ "$GO_MAJOR" -lt 1 ] || { [ "$GO_MAJOR" -eq 1 ] && [ "$GO_MINOR" -lt 25 ]; }; then
    echo "go found, but version $GO_VERSION < 1.25 — amneziawg-go won't build (its go.mod needs 1.25.0+)."
    echo "Install a current one: brew install go (or upgrade yours) and re-run install.sh."
    exit 1
  fi
  mkdir -p bin
  tmp=$(mktemp -d)
  git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-go.git "$tmp/amneziawg-go"
  (cd "$tmp/amneziawg-go" && go build -o "$DIR/bin/amneziawg-go" .)
  rm -rf "$tmp"
  echo "amneziawg-go built -> bin/amneziawg-go"
else
  echo "already built, skipping"
fi

echo "== 2. config.yaml =="
if [ ! -f config.yaml ]; then
  cp config.example.yaml config.yaml
  echo "Created config.yaml from the template — OPEN IT AND FILL IN interface/client.internal_ip before continuing."
  echo "Stopping here, re-run install.sh after editing it."
  exit 0
fi

INTERFACE=$(python3 -c "import yaml; print(yaml.safe_load(open('config.yaml'))['interface'])")

echo "== 3. python dependencies =="
python3 -c "import yaml, cryptography" 2>/dev/null || pip3 install --user pyyaml cryptography

echo "== 4. hub ($HUB): bring the endpoint up, if this config asks for it =="
# Only touches the hub when config.yaml names the unit. It used to hardcode
# awg-quick@awg0, which is wrong for the default (plain wg0) hub and is not a
# laptop's business to decide for a shared server anyway.
# `|| true` and the `or {}` chain both matter under `set -euo pipefail`: a
# `vps:` key present but empty parses as None, and a bare `hub_systemd_unit:`
# with no value parses as None too -- which without this would either abort the
# installer with a Python traceback at step 4, or send the literal string "None"
# to systemctl on a hub shared by the whole fleet.
HUB_UNIT=$(python3 -c "
import yaml
cfg = yaml.safe_load(open('config.yaml')) or {}
print((cfg.get('vps') or {}).get('hub_systemd_unit') or '')
" || true)   # visible if it breaks, never fatal
if [ -z "$HUB_UNIT" ]; then
  echo "no vps.hub_systemd_unit in config.yaml -- leaving the hub alone"
elif case "$HUB_UNIT" in -*|*[!A-Za-z0-9@._-]*) true ;; *) false ;; esac; then
  # ssh hands its command to a shell on the far side, and that shell is root on
  # the hub, so a value carrying a space, semicolon, backtick or newline would
  # run there. Systemd unit names contain none of that.
  #
  # `case` and not `grep -qE '^...$'`: grep succeeds when ANY LINE matches, so
  # a value of "wg-quick@wg0" followed by a newline and "rm -rf /" passed on its
  # first line and handed both lines to the remote root shell. Verified. A
  # leading dash is rejected too, so a mistyped value cannot reach systemctl as
  # an option instead of a unit name.
  echo "vps.hub_systemd_unit is not a plain systemd unit name: '$HUB_UNIT'" >&2
  echo "refusing to send it to $HUB" >&2
  exit 1
else
  # Never fatal: wg mode needs no SSH of its own, and an unreachable hub (no
  # alias, key not loaded, host down) must not kill the installer before
  # anything is set up. Real stderr is shown rather than swallowed, so "unit
  # missing" is not printed for "unit exists but failed to start".
  HUB_ERR=$(mktemp)
  if ssh -o ConnectTimeout=10 -o BatchMode=yes "$HUB" "systemctl enable --now $HUB_UNIT" 2>"$HUB_ERR"; then
    echo "$HUB_UNIT up on $HUB"
  else
    echo "could not bring $HUB_UNIT up on $HUB -- continuing, but the tunnel needs it before step 9 can pass:"
    sed 's/^/    /' "$HUB_ERR"
  fi
  rm -f "$HUB_ERR"
fi

echo "== 5. sync runtime dir ($RUNTIME_DIR) =="
mkdir -p "$RUNTIME_DIR/bin"
cp egress_tunnel.py config.yaml "$RUNTIME_DIR/"
cp bin/amneziawg-go "$RUNTIME_DIR/bin/amneziawg-go"

echo "== 6. LaunchDaemon: interface ($INTERFACE) =="
sed -e "s|__INSTALL_DIR__|$RUNTIME_DIR|g" -e "s|__INTERFACE__|$INTERFACE|g" \
  launchd/org.egress-tunnel.interface.plist.template \
  | sudo tee /Library/LaunchDaemons/org.egress-tunnel.interface.plist > /dev/null
sudo launchctl bootout system/org.egress-tunnel.interface 2>/dev/null || true
# A previous `install.sh proxy` leaves the daemon disabled; bootstrap refuses a disabled one.
sudo launchctl enable system/org.egress-tunnel.interface
sleep 1
sudo launchctl bootstrap system /Library/LaunchDaemons/org.egress-tunnel.interface.plist

sleep 2

echo "== 7. LaunchDaemon: watchdog (health-check + routes) =="
# Not command -v python3 directly: on machines with pyenv that's a shim (a bash
# script), which inside a root LaunchDaemon fails at getcwd/cd before the
# interpreter even starts. sys.executable gives the real binary path, bypassing
# the shim.
PYTHON3=$(python3 -c "import sys; print(sys.executable)")
# HOME is unset for a root system-domain daemon (Path.home() would resolve to
# /var/root instead of this user's home), which is where the private key lands.
# Pin it explicitly so the key ends up in $HOME/.egress-tunnel/private_key.
sed -e "s|__INSTALL_DIR__|$RUNTIME_DIR|g" -e "s|__PYTHON3__|$PYTHON3|g" -e "s|__HOME__|$HOME|g" \
  launchd/org.egress-tunnel.watchdog.plist.template \
  | sudo tee /Library/LaunchDaemons/org.egress-tunnel.watchdog.plist > /dev/null
sudo launchctl bootout system/org.egress-tunnel.watchdog 2>/dev/null || true
sudo launchctl enable system/org.egress-tunnel.watchdog
sleep 1
sudo launchctl bootstrap system /Library/LaunchDaemons/org.egress-tunnel.watchdog.plist

sleep 2

echo "== 8. this machine's public key on the hub =="
# Printed BEFORE the proof loop, not after. On a first install the peer is not
# registered yet, so the handshake cannot complete and the loop below is
# guaranteed to time out -- printing the key afterwards made the user wait out
# the whole timeout before seeing the one thing needed to make it pass.
sudo tail -40 /var/log/egress-tunnel.out.log | grep -A1 "Public key" \
  || echo "(no new key this run -- this machine is already registered)"

echo "== 9. prove the tunnel before switching the fallback off =="
# Learned the hard way on 2026-09-21: the installer used to switch proxy mode off
# the moment the daemons were bootstrapped, before the channel had carried a
# single request. The watchdog then declared the (healthy) channel degraded and
# pulled the AI-domain routes, and because the proxy was already gone the machine
# had no path to Anthropic at all -- the session doing the work lost its own API
# access and could not repair itself. Never remove the fallback until the tunnel
# has actually carried traffic.
PROXY_ACTIVE=no
launchctl print "gui/$(id -u)/org.egress-tunnel.proxy" >/dev/null 2>&1 && PROXY_ACTIVE=yes
# The proof runs either way. It used to be skipped when no proxy was loaded,
# which is exactly a first install -- so a wrong peer key, endpoint or
# obfuscation profile printed "done" over a tunnel that had never carried a
# packet. Only the teardown below is conditional: you cannot remove a fallback
# that is not there.
# Bounded on elapsed time, not iteration count: each pass also spends up to
# --max-time in curl, so "30 x sleep 3" is 90s of sleeping but up to ~6 minutes
# of wall clock in exactly the case that hits it (routes up, tunnel black-holed).
DEADLINE=$(( $(date +%s) + 90 ))
ok=0; iface=""; code=""
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  iface=$(route -n get api.anthropic.com 2>/dev/null | awk '/interface:/{print $2}')
  # --noproxy '*': proxy mode is still live here and would gladly answer on the
  # tunnel's behalf. And 401 specifically, not "curl exited 0": curl succeeds on
  # ANY response, so a captive portal or a geo-block page would pass as proof.
  code=$(curl -s -o /dev/null --max-time 8 --noproxy '*' -w '%{http_code}' \
           https://api.anthropic.com/v1/models || true)
  if [ "$iface" = "$INTERFACE" ] && [ "$code" = "401" ]; then
    ok=$((ok + 1))
    [ "$ok" -ge 3 ] && break
  else
    ok=0
  fi
  sleep 3
done
if [ "$ok" -ge 3 ]; then
  echo "tunnel carries api.anthropic.com on $INTERFACE (HTTP 401)"
  if [ "$PROXY_ACTIVE" = yes ]; then
    echo "switching proxy mode off"
    proxy_off
  fi
else
  echo "WARNING: the tunnel did not carry api.anthropic.com within 90s"
  echo "  (last seen: interface=${iface:-none} http=${code:-none}, wanted $INTERFACE / 401)"
  [ "$PROXY_ACTIVE" = yes ] \
    && echo "Leaving proxy mode exactly as it is, so this machine keeps a working path." \
    || echo "There is no proxy fallback loaded either, so this machine currently has NO path to the API."
  echo "First install? Register the public key printed above as a peer on the hub, then re-run."
  echo "Otherwise: sudo tail -20 /var/log/egress-tunnel.out.log"
  # Non-zero. This run replaced whatever was working before and could not show
  # that the replacement carries traffic; printing "done" and exiting 0 after
  # that is how an unattended re-run hides a machine with no path to the API.
  echo "== finished WITHOUT a proven tunnel =="
  exit 1
fi

echo "== done =="
