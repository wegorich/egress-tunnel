# egress-tunnel

Route only your AI-agent traffic (Claude Code, Codex, and the like) from a
macOS laptop through a hub VPS in a region with unrestricted access, so the
agents keep working from a geo-blocked or filtered network while everything
else on the machine goes out directly at full speed.

Two mechanisms live here, and the installer keeps the machine in exactly one of
them:

```bash
./install.sh         # WireGuard split-tunnel - the default
./install.sh proxy   # HTTP proxy over SSH - the fallback
```

**WireGuard mode** is the one to run: system-wide, no per-tool configuration,
near-native throughput and latency. **Proxy mode** is there for networks where
WireGuard's UDP transport genuinely cannot get through; it costs latency and
most of the throughput, but it only needs `ssh <hub>` to work.

Only the domains listed in `config.yaml` cross the hub. Cloudflare rotates the
addresses of those names every few minutes, faster than a per-IP route can
follow: the app still holds the previous answer after that route is gone, and
the packet leaves by the home line. The published Cloudflare networks (and
Anthropic's own block) are therefore pinned whole, the way a VPN pins a
destination network. Addresses outside those networks still get a host route,
which is kept for a while after DNS drops it.

---

## How it works

A hub VPS runs one WireGuard interface. Each client runs two root LaunchDaemons:

- `amneziawg-go` holding a `utun` interface, and
- a Python watchdog (`egress_tunnel.py watch`) that pins the configured CDN
  networks into that interface, re-resolves the domains on a timer, and adds a
  host route only for addresses that fall outside those networks. It removes
  the routes when the channel is genuinely dead (falling back to the normal
  path) and restores them on recovery.

The client binary is [`amneziawg-go`](https://github.com/amnezia-vpn/amneziawg-go)
in both modes, because it is a strict superset of `wireguard-go`: given a
neutral profile it is plain WireGuard on the wire, and given an obfuscation
profile it adds junk packets and header substitution to avoid being
fingerprinted as WireGuard by DPI.

`install-proxy.sh` is the same idea without routes: an HTTP CONNECT proxy
(`tinyproxy`) on the hub, reached over an `autossh` port-forward, with a PAC
file that sends only the configured hosts through it.

### Plain WireGuard is the default, and that is a measurement

Obfuscation sounds like the safer choice, but it is off by default on purpose.
Measured on one laptop, one Wi-Fi, the two modes ten minutes apart:

| mode | median to a CDN-fronted API | down | up |
|---|---:|---:|---:|
| AmneziaWG, obfuscated | 0.262 s | 55-93 Mbit/s | 104-136 Mbit/s |
| WireGuard, plain | 0.271-0.277 s | 64-86 Mbit/s | 120-136 Mbit/s |

Indistinguishable: the spread within either mode (Wi-Fi, not the tunnel) is
wider than the gap between them. Obfuscation costs nothing measurable, and buys
nothing measurable, on a network that is not actually fingerprinting WireGuard.
So plain is the default (one hub interface for the whole fleet, no profile to
keep in sync), and obfuscation is a documented option you turn on if and when a
network starts blocking the protocol itself.

### Why not Amnezia or NetBird directly

- **Amnezia** does split-tunneling by pinning an IP at the moment a domain is
  added. For CDN-fronted domains the IP rotates, the route goes stale, and
  traffic silently leaks around the tunnel. Confirmed upstream:
  [amnezia-vpn/amnezia-client#927](https://github.com/amnezia-vpn/amnezia-client/issues/927).
  `egress-tunnel` pins Cloudflare's published networks, so an address rotating
  inside them is already routed, and re-resolves on every cycle for anything
  outside those networks.
- **NetBird** solves a different problem (mesh access to servers), with no
  reason to be faster specifically for AI egress.

### Coexisting with another VPN

If another VPN (Amnezia, Tailscale, WARP, ...) owns the default route,
`egress-tunnel` defers the AI-domain routes to it instead of fighting over the
same destinations, and takes them back the moment that VPN goes away. It also
pins an explicit host route to the hub's own endpoint via the physical gateway,
so its own WireGuard transport is never nested inside that other VPN (double
encapsulation roughly halves throughput).

---

## Setup

### 1. Hub - plain WireGuard (Debian/Ubuntu, as root)

```bash
apt-get install -y wireguard
WAN=$(ip route show default | awk '{print $5; exit}')   # eth0, ens3, enp1s0, ...
umask 077; wg genkey | tee /etc/wireguard/wg0.key | wg pubkey   # pubkey goes to clients
# NAT alone is not enough: Ubuntu ships DEFAULT_FORWARD_POLICY="DROP" and
# wg-quick adds no FORWARD rules, so with ufw enabled peers handshake, transfer
# counts up, and nothing leaves the box. Deriving $WAN avoids the equally quiet
# failure of hardcoding a NIC name that does not exist on this host.
cat > /etc/wireguard/wg0.conf <<CONF
[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = $(cat /etc/wireguard/wg0.key)
PostUp   = iptables -t nat -A POSTROUTING -o $WAN -j MASQUERADE; iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o $WAN -j MASQUERADE; iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT
CONF
chmod 600 /etc/wireguard/wg0.conf
sysctl -w net.ipv4.ip_forward=1 && echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wg.conf
systemctl enable --now wg-quick@wg0
ufw allow 51820/udp 2>/dev/null || true
```

Note the interface's public key (`wg show wg0 public-key`) and the hub's public
address; the clients need both.

### 2. Hub - AmneziaWG (obfuscated), optional

Only if plain WireGuard is being fingerprinted. It runs as a second interface
alongside `wg0`, on its own port, so you can migrate peer by peer. Neither half
is packaged for Debian.

```bash
git clone https://github.com/amnezia-vpn/amneziawg-go /tmp/awg-go      # needs Go 1.25+
(cd /tmp/awg-go && go build -o /usr/local/bin/amneziawg-go .)
git clone https://github.com/amnezia-vpn/amneziawg-tools /tmp/awg-tools
(cd /tmp/awg-tools/src && make && make install)                       # awg, awg-quick
WAN=$(ip route show default | awk '{print $5; exit}')

# Order matters: rewrite wg-quick first, then a bare `wg`, or the second
# expression rewrites the `wg-quick` inside `awg-quick` into `aawg-quick`
# (systemd then fails to start the unit with 203/EXEC).
sed -e 's|/usr/bin/wg-quick|/usr/bin/awg-quick|g' -e 's|/usr/bin/wg |/usr/bin/awg |g' \
  /usr/lib/systemd/system/wg-quick@.service > /usr/lib/systemd/system/awg-quick@.service

mkdir -p /etc/amnezia/amneziawg && chmod 700 /etc/amnezia/amneziawg
umask 077; awg genkey | tee /etc/amnezia/amneziawg/awg0.key | awg pubkey
# Generate your OWN Jc/Jmin/Jmax/S1/S2/H1-H4 - a published profile becomes its
# own fingerprint once enough deployments reuse it. Jc: junk packet count before
# the handshake; Jmin/Jmax: their size range; S1/S2: handshake padding; H1-H4:
# four distinct message-type magic numbers.
cat > /etc/amnezia/amneziawg/awg0.conf <<CONF
[Interface]
Address = 10.0.1.1/24
ListenPort = 51821
PrivateKey = $(cat /etc/amnezia/amneziawg/awg0.key)
PostUp   = iptables -t nat -A POSTROUTING -o $WAN -j MASQUERADE; iptables -A FORWARD -i awg0 -j ACCEPT; iptables -A FORWARD -o awg0 -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o $WAN -j MASQUERADE; iptables -D FORWARD -i awg0 -j ACCEPT; iptables -D FORWARD -o awg0 -j ACCEPT
Jc = <int>
Jmin = <int>
Jmax = <int>
S1 = <int>
S2 = <int>
H1 = <uint32>
H2 = <uint32>
H3 = <uint32>
H4 = <uint32>
CONF
chmod 600 /etc/amnezia/amneziawg/awg0.conf
systemctl enable --now awg-quick@awg0
ufw allow 51821/udp 2>/dev/null || true
```

The obfuscation profile must be byte-identical on the hub and on every peer, or
the handshake never parses - the most common way to end up with a tunnel that
looks configured and silently never connects.

### 3. Client (macOS)

```bash
git clone <this-repo> && cd egress-tunnel
cp config.example.yaml config.yaml
```

Edit `config.yaml`: pick a free `interface` (`ifconfig | grep utun` shows
what's taken), a free `client.internal_ip` inside the hub's `/24`, and set
`vps.endpoint` and `vps.peer_public_key` to the hub's. Leave the `obfuscation`
block commented out unless you are joining an AmneziaWG interface. Then:

```bash
./install.sh          # run from your own terminal: it needs an interactive sudo password
```

The run prints this machine's public key. Register it on the hub **without
dropping the peers already connected**:

```bash
# on the hub
cat >> /etc/wireguard/wg0.conf <<CONF

[Peer]
# whose machine this is
PublicKey = <the key install.sh printed>
AllowedIPs = <that machine's client.internal_ip>/32
CONF
wg syncconf wg0 <(wg-quick strip wg0)     # NOT `systemctl restart` - that drops every peer
```

Re-run `./install.sh`. It now has a live tunnel to prove, and once it proves it,
switches proxy mode off.

### Verify

```bash
route -n get api.anthropic.com | grep interface      # your utun, not en0
curl -s -o /dev/null -w '%{http_code}\n' --noproxy '*' https://api.anthropic.com/v1/models
                                                     # 401 = through the tunnel; 403 = going direct
ssh <hub> 'wg show wg0'                               # handshake < ~120s, transfer counting up
sudo tail -20 /var/log/egress-tunnel.out.log         # no repeated "channel degraded"
```

`401` is the pass, not `200` and not "curl exited 0": `curl` reports success for
any HTTP response, so a geo-block page or a captive portal looks like a working
tunnel if you only check the exit code.

---

## Configuration

All client settings live in `config.yaml` (see `config.example.yaml`):

- `interface` - the macOS `utun<N>` to use.
- `vps.endpoint` / `vps.peer_public_key` - the hub's address and interface key.
- `vps.hub_cidr` - the hub's internal subnet; `client.internal_ip` is this
  machine's address within it.
- `vps.hub_systemd_unit` (optional) - when set, `install.sh` runs
  `systemctl enable --now <unit>` on the hub over SSH. Omit it and the hub is
  left alone, the right default when the hub is shared.
- `vps.obfuscation` (optional) - nine AmneziaWG parameters. Omit for plain
  WireGuard. All nine or none.
- `healthcheck.*` - probe URL and interval, and the degrade/recover thresholds.

Switching between plain and obfuscated is more than one key, because the
obfuscated hub is a **separate interface** on its own port and subnet. Four
values move together:

| | plain | obfuscated |
|---|---|---|
| `vps.endpoint` | `<hub>:51820` | `<hub>:51821` |
| `vps.peer_public_key` | `wg0`'s | `awg0`'s |
| `vps.hub_cidr` | `10.0.0.0/24` | `10.0.1.0/24` |
| `client.internal_ip` | in `10.0.0.0/24` | in `10.0.1.0/24` |
| `vps.obfuscation` | omitted | all nine parameters |

Register the client's key on whichever interface you are moving to, then re-run
`./install.sh`. You do not have to clear the previous profile by hand: the
watchdog always writes the full obfuscation block to the interface (neutral
values included), so a stale profile cannot outlive the switch.

---

## Phones and other clients

The smart part of this project (per-domain routing with CDN re-resolution) is a
macOS daemon and does not run on a phone. But the hub is just WireGuard, so a
phone can still use it - with a coarser split:

- **Full tunnel (simplest).** Install the **WireGuard** app (or **AmneziaWG** if
  the hub interface is obfuscated - the stock WireGuard app cannot do
  obfuscation), add a peer config pointing at the hub, and route everything
  through it. Works in a minute.
- **Coarse split.** Set the peer's `AllowedIPs` to specific ranges instead of
  `0.0.0.0/0`. This is static: a mobile client pins IP ranges, not domains, and
  cannot re-resolve, so for CDN-fronted services (most AI APIs) it drifts out of
  date - the exact leak this project's macOS daemon exists to avoid. Use it only
  for stable, non-CDN destinations.

Either way, register the phone as its own `[Peer]` on the hub (its own key, its
own `internal_ip`), the same as a laptop.

## Design notes and hard-won rules

These each cost a real outage to learn. If you are extending this, do not undo
them.

- **Never remove the working path before the new one has answered `401`.** An
  earlier installer switched the proxy off the moment the daemons started,
  before the tunnel had carried a request; the watchdog then pulled the routes
  and the machine had no path to the API at all, including the very session
  doing the work, which could not repair itself. Both directions of `install.sh`
  now prove the new path before tearing the old one down, and `install.sh`
  exits non-zero (never prints "done") if it cannot.

- **`handshake_timeout_sec` must be >= 180.** It looks like a knob to detect
  failure faster; it is not. `PersistentKeepalive` (25 s) holds the NAT mapping
  open but does not refresh the handshake. WireGuard renews the handshake on its
  own `REKEY_AFTER_TIME` (120 s) and only treats a session as dead at
  `REJECT_AFTER_TIME` (180 s). A lower threshold fires on a perfectly healthy
  tunnel - the handshake age climbs to 120 and resets every cycle, so a
  threshold of 75 spent ~45 s of every cycle declaring a live channel dead and
  ripping its routes out. This one masqueraded as "DPI throttling" for a week.

- **Health must prove the tunnel, not the internet.** The health check requires
  a fresh handshake *and* the hub answering inside the tunnel. A plain HTTP
  probe does not qualify: once the routes are torn down it travels the direct
  path, and any HTTP reply (including a geo-block 403) then reads as "recovered"
  - which restores the routes, fails again, and thrashes.

- **Re-applying config while degraded must not re-pin routes.** A replaced
  interface daemon comes up with no key and no peer, so the watchdog
  re-configures it while down - but only the interface, never the routes.
  Pinning AI-domain routes into an interface just declared dead strands that
  traffic, because the teardown that would undo it is gated on being healthy.

- **A peer is added with `wg syncconf`, never a restart.** A restart drops every
  other peer on the hub.

- **`install.sh` is for a human terminal.** It needs an interactive sudo
  password; running it from automation hangs or half-installs.

- **A config value that reaches the hub over SSH is validated first.**
  `vps.hub_systemd_unit` is checked against a strict character set before it is
  interpolated into a remote `systemctl` command running as root.

- **Diagnosing Wi-Fi jitter: don't ping the router.** A consumer router answers
  ICMP addressed to itself from its control plane, last, and reports tens of
  milliseconds where a wired host on the same LAN answers in a fraction of one.
  Ping a real host on the far side, and always measure a known-good path at the
  same moment as the suspect one; conditions change by the hour.

## The `egress_tunnel.py` interface

One script, three subcommands:

- `up` - one-shot setup (keys, interface, routes), for debugging.
- `watch` - `up` plus the health-check and re-resolve loop; this is the
  production mode the LaunchDaemon runs.
- `status` - handshake age and which domains are currently routed. Reports "the
  interface daemon is not answering" distinctly from "never handshaked".

## Layout

```
egress_tunnel.py      the watchdog (UAPI client + routing + health loop)
install.sh            client installer, both modes
install-proxy.sh      proxy-mode installer (tinyproxy + autossh + PAC)
config.example.yaml   copy to config.yaml and fill in
client/ai-egress.pac  which hosts go through the proxy in proxy mode
server/tinyproxy.conf hub-side proxy config for proxy mode
launchd/              LaunchDaemon/LaunchAgent templates
```

## Limitations

- macOS client only (uses `route`/`ifconfig`). A Linux client would need a
  different backend.
- Each machine generates its own key; registering it on the hub is manual.
- A fresh install runs plain WireGuard. That is the measured default, but a
  network that fingerprints WireGuard will affect it until you enable a profile;
  proxy mode is the escape hatch for that case.
