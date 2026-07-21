// proxy.ts — Bun HTTP/HTTPS proxy with PIN auth + IP timeout
import { setDefaultResultOrder } from "node:dns";

setDefaultResultOrder("ipv4first");

// --- Config from environment ---
const PORT = parseInt(Bun.env.PORT ?? "32000", 10);
const PIN = Bun.env.PIN ?? "0000";
// minutes
const TIMEOUT_MIN = parseInt(Bun.env.TIMEOUT ?? "300", 10);
const TIMEOUT_MS = TIMEOUT_MIN * 60 * 1000;

// --- State: IP → expiry timestamp (ms) ---
const allowedIPs = new Map<string, number>();
let isShuttingDown = false;

// --- Logging ---
const ts = () =>
  new Date().toLocaleString("en-GB", { timeZone: "Europe/Moscow" });
const log = (msg: string) => console.log(`[${ts()}] ${msg}`);
const logErr = (msg: string) => console.error(`[${ts()}] [ERROR] ${msg}`);

// --- Expired IP cleanup (every 30s) ---
const cleanupTimer = setInterval(() => {
  const now = Date.now();
  for (const [ip, expires] of allowedIPs) {
    if (now >= expires) {
      allowedIPs.delete(ip);
      log(`IP expired and removed: ${ip}`);
    }
  }
}, 30_000);

// --- IP utilities ---
function ipToInt(ip: string): number {
  return ip.split(".").reduce((n, o) => (n << 8) + parseInt(o, 10), 0) >>> 0;
}

function cidrMatch(cidr: string, ip: string): boolean {
  const [net, bits = "32"] = cidr.split("/");
  const mask = ~((1 << (32 - parseInt(bits, 10))) - 1);
  return (ipToInt(net) & mask) === (ipToInt(ip) & mask);
}

function wildcardMatch(pattern: string, ip: string): boolean {
  const re = new RegExp(
    "^" + pattern.replace(/\./g, "\\.").replace(/\*/g, "[0-9]+") + "$"
  );
  return re.test(ip);
}

function isIPAllowed(ip: string): boolean {
  // Direct entry with timeout check
  const expires = allowedIPs.get(ip);
  if (expires !== undefined) {
    if (Date.now() < expires) return true;
    allowedIPs.delete(ip); // lazy cleanup
    return false;
  }
  // Wildcard / CIDR entries (stored with key like "10.0.0.*" or "10.0.0.0/24")
  for (const [entry, exp] of allowedIPs) {
    if (Date.now() >= exp) continue;
    if (entry.includes("*") && wildcardMatch(entry, ip)) return true;
    if (entry.includes("/") && cidrMatch(entry, ip)) return true;
  }
  return false;
}

function getClientIP(req: Request, srv: any): string {
  const fwd = req.headers.get("x-forwarded-for");
  if (fwd) return fwd.split(",")[0].trim();
  const addr = srv.requestIP(req);
  return addr?.address?.replace(/^::ffff:/, "") ?? "unknown";
}

function msToHuman(ms: number): string {
  const totalMin = Math.floor(ms / 60_000);
  const h = Math.floor(totalMin / 60);
  const m = totalMin % 60;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

// --- HTML pages ---
function pinPage(error = false): Response {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>Proxy Auth</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
    background:#0f172a;color:#e2e8f0;
    display:flex;align-items:center;justify-content:center;
    min-height:100dvh;padding:1rem;
  }
  .card{
    background:#1e293b;border-radius:1rem;padding:2.5rem 2rem;
    width:100%;max-width:340px;text-align:center;
    box-shadow:0 25px 50px -12px rgba(0,0,0,.5);
  }
  h1{font-size:1.4rem;margin-bottom:.5rem}
  p.sub{font-size:.85rem;color:#94a3b8;margin-bottom:1.5rem}
  input[type=password]{
    width:100%;padding:.9rem 1rem;font-size:1.5rem;text-align:center;
    letter-spacing:.6em;border:2px solid #334155;border-radius:.6rem;
    background:#0f172a;color:#f1f5f9;outline:none;transition:border-color .2s;
  }
  input:focus{border-color:#3b82f6}
  input.shake{animation:shake .4s}
  @keyframes shake{
    0%,100%{transform:translateX(0)}
    20%,60%{transform:translateX(-8px)}
    40%,80%{transform:translateX(8px)}
  }
  button{
    width:100%;margin-top:1.2rem;padding:.9rem;font-size:1.05rem;
    font-weight:600;border:none;border-radius:.6rem;cursor:pointer;
    background:#3b82f6;color:#fff;transition:background .2s;
  }
  button:active{background:#2563eb}
  .err{color:#f87171;font-size:.85rem;margin-top:.8rem;min-height:1.2em}
  .timeout-hint{font-size:.75rem;color:#64748b;margin-top:1.2rem}
</style>
</head>
<body>
<div class="card">
  <h1>🔐 Proxy Access</h1>
  <p class="sub">Enter PIN to authorize your IP</p>
  <form method="POST" action="/auth">
    <input type="password" name="pin" inputmode="numeric" pattern="[0-9]*"
      autocomplete="off" maxlength="16" placeholder="••••"
      ${error ? 'class="shake"' : ""} autofocus>
    <button type="submit">Unlock</button>
  </form>
  <div class="err">${error ? "Invalid PIN. Try again." : ""}</div>
  <div class="timeout-hint">Access expires after ${TIMEOUT_MIN} min of inactivity</div>
</div>
</body>
</html>`;
  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

function successPage(ip: string): Response {
  const expiresAt = new Date(Date.now() + TIMEOUT_MS);
  const timeStr = expiresAt.toLocaleString("en-GB", { timeZone: "Europe/Moscow" });
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Access Granted</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
    background:#0f172a;color:#e2e8f0;
    display:flex;align-items:center;justify-content:center;
    min-height:100dvh;padding:1rem;
  }
  .card{
    background:#1e293b;border-radius:1rem;padding:2.5rem 2rem;
    width:100%;max-width:400px;text-align:center;
    box-shadow:0 25px 50px -12px rgba(0,0,0,.5);
  }
  .icon{font-size:3rem;margin-bottom:1rem}
  h1{font-size:1.3rem;color:#4ade80;margin-bottom:1rem}
  .ip{
    font-size:1.5rem;font-weight:700;font-family:"SF Mono",Menlo,monospace;
    background:#0f172a;padding:.7rem 1.2rem;border-radius:.5rem;
    display:inline-block;margin:.5rem 0 1rem;color:#38bdf8;word-break:break-all;
  }
  .meta{font-size:.8rem;color:#94a3b8;margin-bottom:.4rem}
  .meta strong{color:#e2e8f0}
  .countdown{
    margin-top:1.2rem;font-size:2rem;font-weight:700;
    font-family:"SF Mono",Menlo,monospace;color:#facc15;
  }
  .countdown.expired{color:#f87171;font-size:1rem}
  p.note{font-size:.75rem;color:#64748b;margin-top:1.2rem}
</style>
</head>
<body>
<div class="card">
  <div class="icon">✅</div>
  <h1>Your IP is now allowed</h1>
  <div class="ip">${ip}</div>
  <div class="meta">Expires: <strong>${timeStr}</strong> (Moscow)</div>
  <div class="meta">Duration: <strong>${msToHuman(TIMEOUT_MS)}</strong></div>
  <div class="countdown" id="cd"></div>
  <p class="note">Configure your device proxy → this server :${PORT}</p>
</div>
<script>
(function(){
  const end = ${expiresAt.getTime()};
  const el = document.getElementById('cd');
  function tick(){
    const left = end - Date.now();
    if(left <= 0){
      el.textContent = '⏰ Access expired — re-enter PIN';
      el.classList.add('expired');
      return;
    }
    const s = Math.floor(left/1000);
    const h = Math.floor(s/3600);
    const m = Math.floor((s%3600)/60);
    const sec = s%60;
    el.textContent =
      (h>0?h+'h ':'') +
      String(m).padStart(2,'0')+'m '+
      String(sec).padStart(2,'0')+'s';
    setTimeout(tick, 1000);
  }
  tick();
})();
</script>
</body>
</html>`;
  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

// --- Hop-by-hop cleanup ---
const HOP = [
  "connection","keep-alive","proxy-authenticate",
  "proxy-authorization","te","trailers","transfer-encoding","upgrade",
];
function cleanHeaders(h: Headers): Headers {
  const out = new Headers(h);
  for (const k of HOP) out.delete(k);
  out.delete("proxy-connection");
  return out;
}

// --- Server ---
const server = Bun.serve({
  port: PORT,
  idleTimeout: 120,

  async fetch(req: Request, srv): Promise<Response | undefined> {
    const url = new URL(req.url);
    const clientIP = getClientIP(req, srv);

    // --- Auth routes (always open) ---
    if (url.pathname === "/" && req.method === "GET") return pinPage();

    if (url.pathname === "/auth" && req.method === "POST") {
      const body = await req.formData();
      const pin = (body.get("pin") as string) ?? "";
      if (pin === PIN) {
        allowedIPs.set(clientIP, Date.now() + TIMEOUT_MS);
        log(`PIN OK — allowed ${clientIP} for ${TIMEOUT_MIN} min`);
        return successPage(clientIP);
      }
      log(`PIN FAIL from ${clientIP}`);
      return pinPage(true);
    }

    // --- Proxy routes require auth ---
    if (!isIPAllowed(clientIP)) {
      log(`Blocked ${req.method} from unauthorized IP: ${clientIP}`);
      return new Response("403 Forbidden — IP not authorized", { status: 403 });
    }

    // --- CONNECT tunnel (HTTPS) ---
    if (req.method === "CONNECT") {
      const target = url.hostname || url.host;
      const port = parseInt(url.port) || 443;
      log(`CONNECT ${target}:${port} from ${clientIP}`);
      try {
        await Bun.connect({ hostname: target, port });
        return new Response(null, { status: 200 });
      } catch (err: any) {
        logErr(`CONNECT failed ${target}:${port} — ${err.message}`);
        return new Response("502 Bad Gateway", { status: 502 });
      }
    }

    // --- HTTP proxy ---
    log(`HTTP ${req.method} ${req.url} from ${clientIP}`);
    try {
      const headers = cleanHeaders(req.headers);
      headers.set("host", url.host);
      const proxyRes = await fetch(req.url, {
        method: req.method,
        headers,
        body: ["GET", "HEAD"].includes(req.method) ? undefined : req.body,
        // @ts-ignore
        redirect: "manual",
      });
      return new Response(proxyRes.body, {
        status: proxyRes.status,
        statusText: proxyRes.statusText,
        headers: cleanHeaders(proxyRes.headers),
      });
    } catch (err: any) {
      logErr(`Proxy error ${req.url}: ${err.message}`);
      return new Response(`502 Bad Gateway: ${err.message}`, { status: 502 });
    }
  },

  error(err) {
    logErr(`Server error: ${err.message}`);
    return new Response("Internal Server Error", { status: 500 });
  },
});

// --- Startup ---
log(`Proxy on :${PORT} | PIN auth | IP timeout: ${TIMEOUT_MIN} min`);

// --- Graceful shutdown ---
function shutdown() {
  if (isShuttingDown) return;
  isShuttingDown = true;
  log("Shutting down…");
  clearInterval(cleanupTimer);
  server.stop(true);
  process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
