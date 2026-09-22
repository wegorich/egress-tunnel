#!/usr/bin/env python3
"""
egress-tunnel — WireGuard split-tunnel for AI-agent traffic.

A single process owns: the interface (via an already-running amneziawg-go),
health-checking, and dynamic domain re-resolution. No separate service per
function — if any one thing breaks, it's all visible in one log from one
process.

Runs on amneziawg-go rather than plain wireguard-go: same WireGuard crypto,
but with an optional obfuscation layer (junk packets around the handshake,
padded/substituted headers) that keeps this from being fingerprinted as
WireGuard by DPI. When `vps.obfuscation` isn't set in config.yaml, none of
that activates and it behaves exactly like plain WireGuard - see #6 for the
throughput comparison (~10% overhead with obfuscation on).

Why not Amnezia/off-the-shelf VPN clients: their split-tunneling pins the IP
statically when a domain is added (see github.com/amnezia-vpn/amnezia-client
issue #927) — for CDN-fronted domains (Cloudflare-fronted APIs) the IP
changes, the route goes stale, and traffic silently leaks around the tunnel.
This daemon re-resolves domains on every cycle and updates routes when the
IP changes.

Usage:
    egress_tunnel.py up       # one-shot interface + route setup, then exit
    egress_tunnel.py watch    # same, plus an infinite health-check/re-resolve loop (for LaunchDaemon)
    egress_tunnel.py status   # current state: handshake, routes, domains
"""
import base64
import binascii
import ipaddress
import json
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: pip3 install pyyaml")

CONFIG_PATH = Path(__file__).parent / "config.yaml"
KEY_PATH = Path.home() / ".egress-tunnel" / "private_key"


# ------------------------------------------------------------------ keys ---

def b64_to_hex(b64: str) -> str:
    return binascii.hexlify(base64.b64decode(b64)).decode()


def hex_to_b64(hex_str: str) -> str:
    return base64.b64encode(binascii.unhexlify(hex_str)).decode()


def load_or_generate_private_key() -> str:
    """Returns the base64 private key, generating a new one on first run."""
    if KEY_PATH.exists():
        return KEY_PATH.read_text().strip()

    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives import serialization

    priv = x25519.X25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    priv_b64 = base64.b64encode(priv_bytes).decode()

    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    pub_b64 = base64.b64encode(pub_bytes).decode()

    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    KEY_PATH.write_text(priv_b64)
    KEY_PATH.chmod(0o600)

    print(f"New key generated. Public key (add it as a peer on the server):")
    print(f"  {pub_b64}")
    return priv_b64


# ------------------------------------------------------------------ UAPI ---

class WireGuardUAPI:
    """Talks to an already-running amneziawg-go over its control socket.
    Doesn't need wireguard-tools (`wg`)/amneziawg-tools (`awg`) — the whole
    protocol is plain text, and amneziawg-go's is a strict superset of plain
    wireguard-go's (same keys, plus jc/jmin/jmax/s1/s2/h1-h4 for obfuscation).
    One real difference: the socket lives under /var/run/amneziawg, not
    /var/run/wireguard."""

    def __init__(self, interface: str):
        self.sock_path = f"/var/run/amneziawg/{interface}.sock"

    def wait_for_socket(self, timeout: float = 30.0) -> None:
        """Block until the interface daemon has created its control socket.

        launchd starts both daemons at once, and amneziawg-go creates the socket
        a moment after it is exec'd. Without this wait the watchdog reached
        configure() first, died on FileNotFoundError, and was restarted by
        KeepAlive -- a crash loop that ended only when it happened to win the
        race. Seen in /var/log/egress-tunnel.err.log on 2026-09-19 and again on
        2026-09-21."""
        deadline = time.monotonic() + timeout
        last: Exception | None = None
        while time.monotonic() < deadline:
            try:
                # A real round trip, not Path.exists(): a socket file left behind
                # by a killed daemon, or one created a beat before the daemon
                # starts accepting, both pass an existence check and then fail on
                # connect — which is the very race this is here to close.
                self._talk("get=1\n\n")
                return
            except OSError as exc:
                last = exc
                time.sleep(0.5)
        raise RuntimeError(
            f"{self.sock_path} was not answering within {timeout:.0f}s ({last}) — "
            "is org.egress-tunnel.interface running?")

    def _talk(self, message: str) -> str:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5)
        try:
            s.connect(self.sock_path)
            s.sendall(message.encode())
            return s.recv(65536).decode()
        finally:
            s.close()

    def configure(self, private_key_b64: str, peer_public_key_b64: str, endpoint: str,
                  obfuscation: dict | None = None):
        self.wait_for_socket()
        # Always send the whole obfuscation block, including when obfuscation is
        # off. A UAPI `set` applies the keys it carries and leaves the ones it
        # omits alone — it does not reset them. So simply deleting
        # `vps.obfuscation` from config.yaml used to leave a running
        # amneziawg-go still wrapping every packet in junk, aimed at a hub that
        # no longer expects it: a tunnel that looks configured, reports no
        # error, and silently never completes a handshake. Cost an hour on
        # 2026-09-21 before the cause was found.
        #
        # NEUTRAL is what plain WireGuard looks like on the wire: no junk
        # packets, no junk prefixes, and the four standard message types.
        # Verified accepted by amneziawg-go 0.0.20250522 (`errno=0`).
        NEUTRAL = {"jc": 0, "jmin": 0, "jmax": 0, "s1": 0, "s2": 0,
                   "h1": 1, "h2": 2, "h3": 3, "h4": 4}
        if obfuscation:
            # All nine or none. config.example.yaml comments each parameter on
            # its own line, so uncommenting a subset is the natural mistake --
            # and filling the rest from NEUTRAL would silently build a profile
            # the hub cannot parse, which is the failure mode hardest to read
            # from the outside. Name what is missing instead.
            missing = [k for k in NEUTRAL if k not in obfuscation]
            if missing:
                raise ValueError(
                    "vps.obfuscation is incomplete: missing "
                    + ", ".join(missing)
                    + ". All nine parameters must be set and must match the hub exactly.")
        o = obfuscation or NEUTRAL
        obfuscation_lines = "".join(
            f"{k}={o[k]}\n"
            for k in ("jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4")
        )
        config = (
            "set=1\n"
            f"private_key={b64_to_hex(private_key_b64)}\n"
            "listen_port=0\n"
            f"{obfuscation_lines}"
            "replace_peers=true\n"
            f"public_key={b64_to_hex(peer_public_key_b64)}\n"
            f"endpoint={endpoint}\n"
            "persistent_keepalive_interval=25\n"
            "replace_allowed_ips=true\n"
            "allowed_ip=0.0.0.0/0\n"
            "\n"
        )
        resp = self._talk(config)
        if "errno=0" not in resp:
            raise RuntimeError(f"UAPI configure failed: {resp}")

    def last_handshake_age(self) -> float | None:
        """Seconds since the last handshake, or None if there hasn't been one.

        None also covers "the interface daemon is not answering right now" --
        it restarts under us (its own KeepAlive, or install.sh re-bootstrapping
        it) and the watchdog polls this every probe_interval_sec. An unhandled
        socket error here killed the watchdog instead of simply reporting an
        unhealthy channel, and made `egress_tunnel.py status` traceback at
        exactly the moment someone runs it to find out what is wrong."""
        try:
            resp = self._talk("get=1\n\n")
        except OSError:
            return None
        sec = None
        for line in resp.splitlines():
            if line.startswith("last_handshake_time_sec="):
                sec = int(line.split("=", 1)[1])
        if not sec:
            return None
        return time.time() - sec


# --------------------------------------------------------------- routing ---

def run(cmd: list[str], check=True):
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def ensure_interface_up(interface: str, local_ip: str):
    """Assigns the IP to the interface, unless it's already assigned."""
    r = run(["ifconfig", interface], check=False)
    if local_ip not in r.stdout:
        run(["ifconfig", interface, "inet", local_ip, local_ip, "netmask", "255.255.255.0"])


def ensure_peer_network_route(hub_cidr: str, interface: str):
    r = run(["netstat", "-rn", "-f", "inet"], check=False)
    net = hub_cidr.split("/")[0].rsplit(".", 1)[0] + ".0"
    if net not in r.stdout:
        run(["route", "add", "-net", hub_cidr, "-interface", interface], check=False)


def resolve(domain: str) -> set[str]:
    try:
        return {info[4][0] for info in socket.getaddrinfo(domain, None, socket.AF_INET)}
    except socket.gaierror:
        return set()


def add_host_route(ip: str, interface: str):
    run(["route", "add", "-host", ip, "-interface", interface], check=False)


def delete_host_route(ip: str, interface: str):
    run(["route", "delete", "-host", ip], check=False)


def is_ipv4(s: str) -> bool:
    parts = s.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def physical_gateway() -> str | None:
    """Finds the default gateway on a real (non-VPN) interface. Needed to pin
    a bypass route for the VPS endpoint itself: a VPN client that captures the
    default route (Amnezia, WARP, ...) would otherwise nest this tunnel's own
    outer WireGuard UDP transport inside itself, adding a second layer of
    encryption/loss on top and tanking throughput.

    Checks the interface's own flags rather than matching name prefixes
    (utun/ppp/...): every VPN client on macOS brings up its tunnel as a
    POINTOPOINT interface regardless of what it names it, so this holds for
    VPN clients this wasn't specifically written against. Also skips gateways
    that aren't a plain IPv4 address (e.g. a link-layer address on macOS's own
    internet-sharing bridge), since those aren't usable as a `route` gateway."""
    r = run(["netstat", "-rn", "-f", "inet"], check=False)
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0] != "default" or not is_ipv4(parts[1]):
            continue
        netif_info = run(["ifconfig", parts[3]], check=False)
        if "POINTOPOINT" in netif_info.stdout:
            continue
        return parts[1]
    return None


def ensure_endpoint_bypass_route(endpoint: str):
    """Pins a host route for the VPS endpoint via the real physical gateway,
    regardless of whatever else currently owns the default route. Uses `route
    change` first: a plain `route add` is a no-op (silently swallowed by
    check=False) when a host route already exists, which would leave the
    endpoint pointed at a stale gateway after switching networks (e.g. wifi
    roaming) instead of following it to the new one."""
    host = endpoint.rsplit(":", 1)[0]
    gateway = physical_gateway()
    if not gateway:
        return
    for ip in resolve(host):
        r = run(["route", "change", "-host", ip, gateway], check=False)
        if r.returncode != 0:
            run(["route", "add", "-host", ip, gateway], check=False)


def other_vpn_owns_default() -> bool:
    """True when something else (Amnezia, Tailscale, ...) currently owns the
    default route. We defer the AI-domain routes to it instead of fighting
    over the same destinations: in testing, both systems trying to claim the
    same routes caused constant flapping. This only affects the specific
    per-domain routes below, never the default route itself - when another
    VPN is active, everything not in `routes.domains` is untouched and keeps
    going through it exactly as if egress-tunnel weren't installed."""
    # Not "route get default": that resolves the literal "default" table row
    # directly, bypassing Amnezia's (and others') split-default trick
    # (0.0.0.0/1 + 128.0.0.0/1, each more specific than plain 0.0.0.0/0) -
    # it always reports the physical interface even while that trick is
    # actively capturing all real traffic. A real destination IP goes
    # through normal longest-prefix-match and reflects the truth.
    r = run(["route", "-n", "get", "1.1.1.1"], check=False)
    netif = None
    for line in r.stdout.splitlines():
        line = line.strip()
        if line.startswith("interface:"):
            netif = line.split(":", 1)[1].strip()
            break
    if not netif:
        return False
    return "POINTOPOINT" in run(["ifconfig", netif], check=False).stdout


# ---------------------------------------------------------- health-check ---

def probe_ok(url: str, timeout: float = 5.0) -> bool:
    try:
        req = urllib.request.Request(url, method="HEAD")
        urllib.request.urlopen(req, timeout=timeout)
        return True
    except Exception:
        # An HTTP-level error (404 etc.) still means "the connection went
        # through" — we care about reachability, not the response code.
        return True if isinstance(sys.exc_info()[1], urllib.error.HTTPError) else False


# ------------------------------------------------------------------ core ---

class EgressTunnel:
    def __init__(self, config: dict):
        self.cfg = config
        self.interface = config["interface"]
        self.local_ip = config["client"]["internal_ip"]
        self.hub_cidr = config["vps"]["hub_cidr"]
        # The hub's own address inside the tunnel: first host of hub_cidr by
        # convention (10.0.0.1 for 10.0.0.0/24). Only used as a reachability
        # target; override with healthcheck.tunnel_probe_host if your hub sits
        # somewhere else in the subnet.
        self.hub_ip = str(ipaddress.ip_network(self.hub_cidr, strict=False).network_address + 1)
        self.domains = config["routes"]["domains"]
        self.uapi = WireGuardUAPI(self.interface)
        self.known_ips: dict[str, set[str]] = {}  # domain -> currently routed IPs
        self.healthy = True
        self.consecutive_fail = 0
        self.consecutive_ok = 0
        self.deferring = False  # true while another VPN owns the default route

    def configure_interface(self):
        """Everything needed to make the tunnel itself work, and nothing that
        sends application traffic into it.

        Split out from bring_up() so the watchdog can re-apply the configuration
        while the channel is DOWN — a replaced amneziawg-go comes up with no key
        and no peer — without also pinning the AI domains into an interface we
        have just declared dead. Doing both at once left those routes on a dead
        interface for good: the teardown that would have removed them is guarded
        by self.healthy, which stays False."""
        vps = self.cfg["vps"]
        if "obfuscation" in vps and not isinstance(vps.get("obfuscation"), dict):
            # `obfuscation:` with the parameters left commented underneath parses
            # as None, which .get() cannot tell from "absent" — so the tunnel came
            # up as plain WireGuard against an obfuscated hub: errno=0, no log, no
            # handshake, ever. Comment the key out too, or fill in all nine.
            raise ValueError(
                "vps.obfuscation is present but empty. Comment the whole block out "
                "to run plain WireGuard, or fill in all nine parameters.")
        ensure_endpoint_bypass_route(self.cfg["vps"]["endpoint"])
        priv = load_or_generate_private_key()
        self.uapi.configure(priv, self.cfg["vps"]["peer_public_key"], self.cfg["vps"]["endpoint"],
                             self.cfg["vps"].get("obfuscation"))
        ensure_interface_up(self.interface, self.local_ip)
        ensure_peer_network_route(self.hub_cidr, self.interface)

    def bring_up(self):
        self.configure_interface()
        self.deferring = other_vpn_owns_default()
        if self.deferring:
            print("[egress-tunnel] another VPN owns the default route, deferring AI-domain routing to it")
        else:
            self.refresh_routes()

    def refresh_routes(self):
        """Re-resolves domains, adds new IPs, removes ones that disappeared.
        This is the actual fix for the Amnezia bug — no static IP pinning."""
        ensure_endpoint_bypass_route(self.cfg["vps"]["endpoint"])
        for domain in self.domains:
            current = resolve(domain)
            if not current:
                continue
            previous = self.known_ips.get(domain, set())
            for ip in current - previous:
                add_host_route(ip, self.interface)
            for ip in previous - current:
                delete_host_route(ip, self.interface)
            self.known_ips[domain] = current

    def teardown_routes(self):
        """Removes routes on degradation — traffic falls back to the normal default route."""
        for ips in self.known_ips.values():
            for ip in ips:
                delete_host_route(ip, self.interface)
        self.known_ips.clear()

    def hub_reachable(self) -> bool:
        """Can we reach the hub's own address inside the tunnel?

        This is the only reachability question with the same meaning in both
        states. probe_url does not have it: once the routes are torn down the
        probe leaves by the normal path, and probe_ok() counts any HTTP reply as
        success — so the geo-blocked 403 that direct egress returns here was
        being read as "channel recovered". That declared recovery, bring_up()
        pinned the routes again, the next check failed, and the pair repeated:
        the degrade/recover thrash in egress-tunnel.out.log."""
        host = self.cfg["healthcheck"].get("tunnel_probe_host") or self.hub_ip
        return run(["ping", "-c", "1", "-W", "2000", host], check=False).returncode == 0

    def check_health(self) -> bool:
        age = self.uapi.last_handshake_age()
        if age is None or age > self.cfg["healthcheck"]["handshake_timeout_sec"]:
            return False
        if not self.hub_reachable():
            return False
        # End-to-end only while the routes are actually pinned — that is the only
        # time probe_url travels through the tunnel and means anything. While
        # degraded or deferring, a live tunnel is all we require to come back.
        if self.healthy and not self.deferring:
            return probe_ok(self.cfg["healthcheck"]["probe_url"])
        return True

    def watch(self):
        interval = self.cfg["healthcheck"]["probe_interval_sec"]
        fail_threshold = self.cfg["healthcheck"]["fallback_after_failures"]
        recover_threshold = self.cfg["healthcheck"]["recovery_after_successes"]
        resolve_every = self.cfg["healthcheck"].get("resolve_interval_sec", 300)
        last_resolve = time.time()  # bring_up() already resolved once, just before this

        while True:
            ok = self.check_health()
            if ok:
                self.consecutive_ok += 1
                self.consecutive_fail = 0
                if not self.healthy and self.consecutive_ok >= recover_threshold:
                    print("[egress-tunnel] channel recovered, restoring routes")
                    self.bring_up()
                    self.healthy = True
                    # bring_up() ends in refresh_routes() when not deferring, so
                    # the routes are already back; just keep the resolve clock
                    # honest so the next periodic refresh is measured from here.
                    last_resolve = time.time()
            else:
                self.consecutive_fail += 1
                self.consecutive_ok = 0
                if self.healthy and self.consecutive_fail >= fail_threshold:
                    print("[egress-tunnel] channel degraded, removing routes (falling back to the normal path)")
                    self.teardown_routes()
                    self.healthy = False
                if not self.healthy and self.consecutive_fail % fail_threshold == 0:
                    # Re-apply the configuration while we are down. The interface
                    # daemon can be replaced under us — its own KeepAlive, or
                    # install.sh re-bootstrapping it — and a fresh amneziawg-go
                    # comes up with no key and no peer, so it can never handshake
                    # on its own. Health would then never return and the watchdog
                    # would sit degraded forever. (Before wait_for_socket existed
                    # this healed by accident: the watchdog crashed, launchd
                    # restarted it, and bring_up() ran on the way in.)
                    try:
                        self.configure_interface()
                    except Exception as exc:
                        print(f"[egress-tunnel] re-configure while degraded failed: {exc}")

            if self.healthy:
                now_deferring = other_vpn_owns_default()
                if now_deferring != self.deferring:
                    # React immediately on a state change (VPN toggled on/off)
                    # rather than waiting for the next resolve_every cycle.
                    self.deferring = now_deferring
                    if now_deferring:
                        print("[egress-tunnel] another VPN owns the default route, deferring AI-domain routing to it")
                        self.teardown_routes()
                    else:
                        print("[egress-tunnel] default route is free again, taking over AI-domain routing")
                        self.refresh_routes()
                        last_resolve = time.time()
                elif not now_deferring and time.time() - last_resolve > resolve_every:
                    self.refresh_routes()
                    last_resolve = time.time()

            time.sleep(interval)

    def status(self):
        print(f"interface: {self.interface}")
        # last_handshake_age() folds a dead control socket into None, which is
        # right for the watch loop and wrong here: "never" and "the interface
        # daemon is not running" are the two answers an operator is choosing
        # between, and they are the reason they ran this command.
        try:
            self.uapi.wait_for_socket(timeout=2)
        except RuntimeError:
            print("handshake: unknown — the interface daemon is not answering "
                  f"on {self.uapi.sock_path}")
        else:
            age = self.uapi.last_handshake_age()
            print(f"handshake age: {age:.1f}s" if age is not None else "handshake: never")
        print(f"deferring to another VPN: {self.deferring}")
        print(f"routed domains: {list(self.known_ips.keys()) or '(none yet — run `up` first)'}")


def load_config() -> dict:
    if not CONFIG_PATH.exists():
        sys.exit(f"Config not found: {CONFIG_PATH}. Copy config.example.yaml -> config.yaml")
    return yaml.safe_load(CONFIG_PATH.read_text())


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ("up", "watch", "status"):
        sys.exit(__doc__)

    cfg = load_config()
    tunnel = EgressTunnel(cfg)

    if sys.argv[1] == "up":
        tunnel.bring_up()
        tunnel.status()
    elif sys.argv[1] == "watch":
        tunnel.bring_up()
        tunnel.watch()
    elif sys.argv[1] == "status":
        tunnel.status()


if __name__ == "__main__":
    main()
