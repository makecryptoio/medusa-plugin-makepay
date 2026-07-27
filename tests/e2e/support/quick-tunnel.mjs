const createdMarker = "Your quick Tunnel has been created!";
const quickTunnelUrlPattern =
  /https:\/\/[a-z0-9-]+\.trycloudflare\.com\b/i;

export function extractCreatedQuickTunnelUrl(output) {
  const value = String(output);
  const markerIndex = value.lastIndexOf(createdMarker);
  if (markerIndex === -1) return undefined;

  const match = value.slice(markerIndex).match(quickTunnelUrlPattern);
  if (!match) return undefined;

  const url = new URL(match[0]);
  if (url.hostname === "api.trycloudflare.com") return undefined;
  return url.href.replace(/\/$/, "");
}
