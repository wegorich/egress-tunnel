// Which hosts go through the hub: the Anthropic and OpenAI families, widened
// with the web/auth/CDN hosts that browsers and desktop apps hit. An api-only
// list is enough for a server; a laptop needs the browser-facing names too.
var VIA_HUB = [
  "anthropic.com",
  "claude.ai",
  "claude.com",
  "claudeusercontent.com",
  "openai.com",
  "chatgpt.com",
  "oaistatic.com",
  "oaiusercontent.com",
  "sora.com"
];

function FindProxyForURL(url, host) {
  host = host.toLowerCase();
  for (var i = 0; i < VIA_HUB.length; i++) {
    var d = VIA_HUB[i];
    if (host === d || dnsDomainIs(host, "." + d)) {
      // Deliberately fails OPEN. If autossh or tinyproxy is down the browser
      // falls through to DIRECT, which on this network means a geo-blocked 403
      // rather than a dead tab. Reviewed and kept 2026-09-21: proxy mode is the
      // fallback now, so a soft landing beats a hard one. Drop "; DIRECT" if you
      // ever want these hosts to fail loudly instead of leaking to the ISP.
      return "PROXY 127.0.0.1:8888; DIRECT";
    }
  }
  return "DIRECT";
}
