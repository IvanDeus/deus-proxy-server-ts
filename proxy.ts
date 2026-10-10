// proxy.ts
import { createServer, IncomingMessage, ServerResponse, request as httpRequest } from 'http';
import { parse as urlParse, Url } from 'url';
import { connect as netConnect, Socket } from 'net';
import { setDefaultResultOrder } from 'dns';
import './logger';

// Set DNS to prefer IPv4 but fall back to IPv6
setDefaultResultOrder('ipv4first');

// --- Config ---
const PORT = parseInt(Bun.env.PORT ?? "32000", 10);
const AUTHPORT = parseInt(Bun.env.AUTHPORT ?? "32001", 10);
const TELEGRAM_BOT_TOKEN = Bun.env.TELEGRAM_BOT_TOKEN;
const CHANNEL_ID = Bun.env.CHANNEL_ID;
const PIN_TIMEOUT_MIN = 2; // 2 minutes for dynamic PINs
const TIMEOUT_MIN = parseInt(Bun.env.TIMEOUT ?? "300", 10);
const TIMEOUT_MS = TIMEOUT_MIN * 60000;

// Validate Telegram credentials on startup
if (!TELEGRAM_BOT_TOKEN || !CHANNEL_ID) {
  console.error("❌ TELEGRAM_BOT_TOKEN and CHANNEL_ID environment variables are required");
  process.exit(1);
}

// Test Telegram API connectivity at startup
async function testTelegramConnectivity(): Promise<boolean> {
  try {
    const response = await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getMe`, {
      method: 'GET',
      timeout: 5000 // 5 second timeout
    });
    
    if (response.ok) {
      log("✅ Telegram Bot API is reachable");
      return true;
    } else {
      logErr(`⚠️ Telegram Bot API returned ${response.status}`);
      return false;
    }
  } catch (error) {
    logErr(`⚠️ Cannot reach api.telegram.org - ${(error as Error).message}. PIN delivery will fail until network is fixed.`);
    return false;
  }
}

// --- State ---
const allowedIPs = new Map<string, number>();
const activePINs = new Map<string, { ip: string; expiresAt: number }>();
const activeConnections = new Set<Socket>();
let isShuttingDown = false;

// --- Logging ---
// logger.ts patches the console to prefix every line with a timestamp, so these
// add no stamp of their own.
const log = (msg: string) => console.log(msg);
const logErr = (msg: string) => console.error(`[ERROR] ${msg}`);

const fmtMB = (bytes: number): string => `${(bytes / 1048576).toFixed(2)} MB (${bytes} bytes)`;

// Generate a random 5-digit PIN
function generatePIN(): string {
  return Math.floor(10000 + Math.random() * 90000).toString();
}

// Send PIN via Telegram Bot API
async function sendPINToTelegram(pin: string, clientIP: string): Promise<boolean> {
  const message = `🔐 New Proxy Access PIN\n📍 Requested from IP: ${clientIP}\n⏰ Valid for 2 minutes\n\nYour PIN: **${pin}**`;
  
  try {
    const response = await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: CHANNEL_ID,
        text: message,
        parse_mode: 'Markdown'
      })
    });
    
    if (!response.ok) {
      const errorText = await response.text();
      logErr(`Telegram API error ${response.status}: ${errorText.substring(0, 100)}`);
      return false;
    }
    
    return true;
  } catch (error) {
    logErr(`Telegram fetch failed: ${(error as Error).message}`);
    return false;
  }
}

// Count bytes flowing through a readable stream and report them once, when the
// stream ends or the connection drops (aborted requests still get accounted).
function logDownload(source: Socket | IncomingMessage, describe: () => string): void {
  let bytes = 0;
  let reported = false;
  const report = () => {
    if (reported) return;
    reported = true;
    log(`Downloaded ${fmtMB(bytes)} for ${describe()}`);
  };
  source.on('data', (chunk: Buffer) => { bytes += chunk.length; });
  source.on('end', report);
  source.on('close', report);
  source.on('error', report);
}

// --- Expired IP cleanup ---
const cleanupTimer = setInterval(() => {
  const now = Date.now();
  
  // Clean up expired PINs
  for (const [pin, data] of activePINs) {
    if (now >= data.expiresAt) {
      activePINs.delete(pin);
      log(`PIN expired: ${pin}`);
    }
  }
  
  // Clean up expired IPs
  for (const [ip, exp] of allowedIPs) {
    if (now >= exp) {
      allowedIPs.delete(ip);
      log(`IP expired: ${ip}`);
    }
  }
}, 30_000);

// --- IP utilities ---
function isIPAllowed(clientIP: string): boolean {
  const exp = allowedIPs.get(clientIP);
  if (exp !== undefined) {
    if (Date.now() < exp) return true;
    allowedIPs.delete(clientIP); // Expired, clean up
  }
  return false;
}

function getClientIP(req: IncomingMessage): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded && typeof forwarded === 'string') {
    return forwarded.split(',')[0].trim();
  }
  return (req.socket.remoteAddress?.replace(/^::ffff:/, '') || 'unknown');
}

// --- Connection Tracking ---
function trackConnection(socket: Socket, description: string): void {
  if (isShuttingDown) {
    socket.destroy();
    return;
  }

  const connectionId = `${description}-${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
  (socket as any)._connectionId = connectionId;
  activeConnections.add(socket);

  const cleanup = () => {
    if (activeConnections.has(socket)) {
      activeConnections.delete(socket);
      log(`Connection closed: ${connectionId} (${activeConnections.size} remaining)`);
    }
  };

  socket.on('close', cleanup);
  socket.on('error', cleanup);
  socket.on('end', cleanup);

  log(`New connection: ${connectionId} (${activeConnections.size} total)`);
}

function destroyAllConnections(): void {
  log(`\nForcefully closing ${activeConnections.size} active connections...`);
  activeConnections.forEach(socket => {
    try {
      socket.destroy();
    } catch (err) {
      // Ignore errors during destruction
    }
  });
  activeConnections.clear();
}

// --- HTML Pages ---
function msToHuman(ms: number): string {
  const m = Math.floor(ms / 60_000);
  const h = Math.floor(m / 60);
  return h > 0 ? `${h}h ${m % 60}m` : `${m}m`;
}

function pinPage(error = false, clientIP = 'unknown'): string {
  return `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>Proxy Auth</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;
min-height:100dvh;padding:1rem}
.card{background:#1e293b;border-radius:1rem;padding:2.5rem 2rem;width:100%;max-width:340px;
text-align:center;box-shadow:0 25px 50px -12px rgba(0,0,0,.5)}
h1{font-size:1.4rem;margin-bottom:.5rem}
.subip{font-size:.75rem;color:#64748b;font-family:"SF Mono",Menlo,monospace;margin-bottom:1.5rem}
input[type=password]{width:100%;padding:.9rem 1rem;font-size:1.2rem;text-align:center;
letter-spacing:.25em;border:2px solid #334155;border-radius:.6rem;background:#0f172a;
color:#f1f5f9;outline:none;transition:border-color .2s}
input:focus{border-color:#3b82f6}
input.shake{animation:shake .4s}
@keyframes shake{0%,100%{transform:translateX(0)}20%,60%{transform:translateX(-8px)}40%,80%{transform:translateX(8px)}}
button{width:100%;margin-top:1.2rem;padding:.9rem;font-size:1.05rem;font-weight:600;border:none;
border-radius:.6rem;cursor:pointer;background:#3b82f6;color:#fff;transition:background .2s}
button:active{background:#2563eb}
button:disabled{background:#475569;cursor:not-allowed}
.err{color:#f87171;font-size:.85rem;margin-top:.8rem;min-height:1.2em}
.status{color:#4ade80;font-size:.9rem;margin-top:1rem;padding:1rem;background:#0f172a;border-radius:.5rem}
.hint{font-size:.75rem;color:#64748b;margin-top:1.2rem}
</style></head><body>
<div class="card">
<h1>🔐 Proxy Access</h1>
<p class="subip">From: ${clientIP}</p>
<p class="sub">Get PIN from Telegram to authorize your IP</p>
<button id="getPinBtn" onclick="getPin()">📱 Get PIN via Telegram</button>
<div id="pinStatus"></div>
<form method="POST" action="/auth" id="authForm" style="display:none;margin-top:1.5rem">
<input type="password" name="pin" inputmode="numeric" pattern="[0-9]*"
autocomplete="off" maxlength="5" placeholder="• • • •" ${error ? 'class="shake"' : ""}>
</form>
<div class="err">${error ? "Invalid PIN. Try again." : ""}</div>
<div class="hint">PIN valid for 2 minutes • expires after use</div>
</div></body>
<script>
async function getPin() {
  const btn = document.getElementById('getPinBtn');
  const status = document.getElementById('pinStatus');
  const form = document.getElementById('authForm');
  
  btn.disabled = true;
  btn.textContent = 'Sending...';
  status.innerHTML = '';
  form.style.display = 'none';
  
  try {
    const response = await fetch('/get-pin', { method: 'POST' });
    if (response.ok) {
      status.innerHTML = '<div class="status">✅ PIN sent! Check your Telegram channel.</div>';
      btn.style.display = 'none';
      form.style.display = 'block';
      
      // Focus on PIN input after showing it
      setTimeout(() => {
        const pinInput = form.querySelector('input[name="pin"]');
        if (pinInput) pinInput.focus();
      }, 100);
    } else {
      status.innerHTML = '<div style="color:#f87171;">❌ Failed to send PIN. Please try again.</div>';
      btn.disabled = false;
      btn.textContent = '📱 Get PIN via Telegram';
    }
  } catch (err) {
    status.innerHTML = '<div style="color:#f87171;">❌ Network error. Please try again.</div>';
    btn.disabled = false;
    btn.textContent = '📱 Get PIN via Telegram';
  }
}

// Auto-submit when 5 digits are entered
const pinInput = document.querySelector('input[name="pin"]');
if (pinInput) {
  pinInput.addEventListener('input', (e) => {
    if (e.target.value.length === 5) {
      e.target.closest('form').submit();
    }
  });
}

// Add 2-second cooldown on Get PIN button to prevent DOS
const originalGetPin = getPin;
let pinCooldown = false;
getPin = async () => {
  if (pinCooldown) return;
  pinCooldown = true;
  await new Promise(resolve => setTimeout(resolve, 2000));
  pinCooldown = false;
  return originalGetPin();
};
</script>`;
}

function successPage(ip: string): string {
  const expiresAt = new Date(Date.now() + TIMEOUT_MS);
  const timeStr = expiresAt.toLocaleString("en-GB", { timeZone: "Europe/Moscow" });
  return `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Access Granted</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;
min-height:100dvh;padding:1rem}
.card{background:#1e293b;border-radius:1rem;padding:2.5rem 2rem;width:100%;max-width:400px;
text-align:center;box-shadow:0 25px 50px -12px rgba(0,0,0,.5)}
.icon{font-size:3rem;margin-bottom:1rem}
h1{font-size:1.3rem;color:#4ade80;margin-bottom:1rem}
.ip{font-size:1.5rem;font-weight:700;font-family:"SF Mono",Menlo,monospace;background:#0f172a;
padding:.7rem 1.2rem;border-radius:.5rem;display:inline-block;margin:.5rem 0 1rem;
color:#38bdf8;word-break:break-all}
.meta{font-size:.8rem;color:#94a3b8;margin-bottom:.4rem}
.meta strong{color:#e2e8f0}
.countdown{margin-top:1.2rem;font-size:2rem;font-weight:700;
font-family:"SF Mono",Menlo,monospace;color:#facc15}
.countdown.expired{color:#f87171;font-size:1rem}
p.note{font-size:.75rem;color:#64748b;margin-top:1.2rem}
</style></head><body>
<div class="card">
<div class="icon">✅</div>
<h1>Your IP is now allowed</h1>
<div class="ip">${ip}</div>
<div class="meta">Expires: <strong>${timeStr}</strong> (Moscow)</div>
<div class="meta">Duration: <strong>${msToHuman(TIMEOUT_MS)}</strong></div>
<div class="countdown" id="cd"></div>
<p class="note">Set your device proxy → this server :${PORT}</p>
</div>
<script>
(function(){
  const end=${expiresAt.getTime()},el=document.getElementById('cd');
  function tick(){
    const left=end-Date.now();
    if(left<=0){el.textContent='⏰ Expired — re-enter PIN';el.classList.add('expired');return}
    const s=Math.floor(left/1000),h=Math.floor(s/3600),m=Math.floor(s%3600/60),sec=s%60;
    el.textContent=(h>0?h+'h ':'')+String(m).padStart(2,'0')+'m '+String(sec).padStart(2,'0')+'s';
    setTimeout(tick,1000);
  }
  tick();
})();
</script></body></html>`;
}

// --- Auth Server ---
const authServer = createServer((req, res) => {
  const clientIP = getClientIP(req);
  
  if (req.method === 'GET' && req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(pinPage(false, clientIP));
    return;
  }
  
  // New: Get PIN via Telegram endpoint
  if (req.method === 'POST' && req.url === '/get-pin') {
    const pin = generatePIN();
    const expiresAt = Date.now() + PIN_TIMEOUT_MIN * 60 * 1000;
    
    activePINs.set(pin, { ip: clientIP, expiresAt });
    
    log(`Generated new PIN ${pin.substring(0, 3)}... for ${clientIP}, expires in ${PIN_TIMEOUT_MIN} min`);
    
    sendPINToTelegram(pin, clientIP).then(success => {
      if (success) {
        log(`✅ PIN sent successfully to Telegram for ${clientIP}`);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
      } else {
        logErr(`❌ Failed to send PIN to Telegram for ${clientIP}`);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'Failed to send PIN via Telegram' }));
        activePINs.delete(pin); // Remove failed PIN
      }
    }).catch(err => {
      logErr(`⚠️ Unexpected error in sendPINToTelegram: ${(err as Error).message}`);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: 'Unexpected error sending PIN' }));
      activePINs.delete(pin);
    });
    
    return;
  }

  if (req.method === 'GET' && req.url?.startsWith('/success')) {
    const urlParams = new URLSearchParams(req.url.split('?')[1]);
    const ip = urlParams.get('ip') || clientIP;
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(successPage(ip));
    return;
  }

  if (req.method === 'POST' && req.url === '/auth') {
    let body = '';
    req.on('data', chunk => { body += chunk.toString(); });
    req.on('end', () => {
      // 2200 ms delay to mitigate brute force and timing attacks
      setTimeout(() => {
        const params = new URLSearchParams(body);
        const pin = params.get('pin') ?? '';
        
        // Check if PIN exists and is valid
        if (activePINs.has(pin)) {
          const record = activePINs.get(pin);
          
          // Verify PIN hasn't expired and IP matches
          if (record && Date.now() < record.expiresAt && record.ip === clientIP) {
            allowedIPs.set(clientIP, Date.now() + TIMEOUT_MS);
            activePINs.delete(pin); // Consume PIN after successful use
            log(`PIN OK — allowed ${clientIP} for ${TIMEOUT_MIN} min`);
            res.writeHead(302, { 'Location': `/success?ip=${encodeURIComponent(clientIP)}` });
            res.end();
            return;
          } else {
            activePINs.delete(pin); // Expired or already used - remove it
          }
        }
        
        log(`PIN FAIL from ${clientIP}`);
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(pinPage(false, clientIP)); // Reset form without shake
      }, 2200);
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not Found');
});

// --- Proxy Server ---
const proxyServer = createServer();

function removeHopByHopHeaders(headers: { [key: string]: string | string[] | undefined }): void {
  const hopByHopHeaders = [
    'connection', 'keep-alive', 'proxy-authenticate',
    'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade'
  ];
  hopByHopHeaders.forEach(header => {
    delete headers[header];
  });
}

proxyServer.on('request', (clientReq: IncomingMessage, clientRes: ServerResponse) => {
  const clientIP = getClientIP(clientReq);

  if (!isIPAllowed(clientIP)) {
    log(`Blocked HTTP request from unauthorized IP: ${clientIP}`);
    clientRes.writeHead(403, { 'Content-Type': 'text/plain' });
    clientRes.end('Access denied: Your IP is not authorized. Please authenticate via the auth port.');
    return;
  }

  log(`Proxying HTTP request from ${clientIP}: ${clientReq.method} ${clientReq.url}`);

  const parsedUrl: Url = urlParse(clientReq.url || '');
  if (!parsedUrl.hostname) {
    clientRes.writeHead(400, { 'Content-Type': 'text/plain' });
    clientRes.end('Bad Request: Invalid URL');
    return;
  }

  const options = {
    hostname: parsedUrl.hostname,
    port: parsedUrl.port || 80,
    path: parsedUrl.path || '/',
    method: clientReq.method,
    headers: { ...clientReq.headers },
    family: 4
  };

  options.headers.host = parsedUrl.host || parsedUrl.hostname;
  delete options.headers['proxy-connection'];
  delete options.headers['connection'];
  delete options.headers['keep-alive'];

  trackConnection(clientReq.socket, `HTTP-${clientIP}`);
  trackConnection(clientRes.socket, `HTTP-RES-${clientIP}`);

  const requestDesc = () => `${clientReq.method} ${clientReq.url} via ${parsedUrl.hostname} for ${clientIP}`;

  const proxyReq = httpRequest(options, (proxyRes: IncomingMessage) => {
    removeHopByHopHeaders(proxyRes.headers as any);
    clientRes.writeHead(proxyRes.statusCode || 500, proxyRes.headers);
    logDownload(proxyRes, requestDesc);
    proxyRes.pipe(clientRes);
  });

  proxyReq.on('socket', (socket: Socket) => {
    trackConnection(socket, `HTTP-PROXY-${parsedUrl.hostname}`);
  });

  proxyReq.on('error', (err: NodeJS.ErrnoException) => {
    logErr(`Proxy request error for ${parsedUrl.hostname}: ${err.code}`);

    if (err.code === 'ENOTFOUND' || err.code === 'EAI_FAIL') {
      log(`Retrying ${parsedUrl.hostname} without IP family restriction...`);
      const fallbackOptions = { ...options };
      delete (fallbackOptions as any).family;

      const fallbackReq = httpRequest(fallbackOptions, (fallbackRes: IncomingMessage) => {
        removeHopByHopHeaders(fallbackRes.headers as any);
        clientRes.writeHead(fallbackRes.statusCode || 500, fallbackRes.headers);
        logDownload(fallbackRes, requestDesc);
        fallbackRes.pipe(clientRes);
      });

      fallbackReq.on('socket', (socket: Socket) => {
        trackConnection(socket, `HTTP-FALLBACK-${parsedUrl.hostname}`);
      });

      fallbackReq.on('error', (fallbackErr: NodeJS.ErrnoException) => {
        logErr(`Fallback request also failed for ${parsedUrl.hostname}: ${fallbackErr.code}`);
        clientRes.writeHead(502, { 'Content-Type': 'text/plain' });
        clientRes.end('Proxy error: ' + fallbackErr.message);
      });

      clientReq.pipe(fallbackReq);
    } else {
      clientRes.writeHead(502, { 'Content-Type': 'text/plain' });
      clientRes.end('Proxy error: ' + err.message);
    }
  });

  proxyReq.setTimeout(10000, () => {
    log(`HTTP request timeout for: ${parsedUrl.hostname}`);
    proxyReq.destroy();
    clientRes.writeHead(504, { 'Content-Type': 'text/plain' });
    clientRes.end('Gateway Timeout');
  });

  clientReq.pipe(proxyReq);
});

// Handle CONNECT method for HTTPS tunneling
proxyServer.on('connect', (clientReq: IncomingMessage, clientSocket: Socket, head: Buffer) => {
  const clientIP = getClientIP(clientReq);

  if (!isIPAllowed(clientIP)) {
    log(`Blocked HTTPS request from unauthorized IP: ${clientIP}`);
    clientSocket.end('HTTP/1.1 403 Forbidden\r\n\r\nAccess denied: Your IP is not authorized. Please authenticate via the auth port.');
    return;
  }

  log(`Proxying HTTPS request from ${clientIP}: CONNECT ${clientReq.url}`);

  const urlParts = (clientReq.url || '').split(':');
  const hostname = urlParts[0];
  const serverPort = parseInt(urlParts[1]) || 443;

  trackConnection(clientSocket, `HTTPS-CLIENT-${clientIP}`);

  const tunnelDesc = () => `CONNECT ${hostname}:${serverPort} for ${clientIP}`;

  const serverSocket = netConnect({
    host: hostname,
    port: serverPort,
    family: 4
  }, () => {
    log(`Successfully connected to ${hostname}:${serverPort} for client ${clientIP}`);
    trackConnection(serverSocket, `HTTPS-SERVER-${hostname}`);
    logDownload(serverSocket, tunnelDesc);

    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head && head.length > 0) {
      serverSocket.write(head);
    }
    serverSocket.pipe(clientSocket);
    clientSocket.pipe(serverSocket);
  });

  serverSocket.on('error', (err: NodeJS.ErrnoException) => {
    logErr(`Server socket error for ${hostname}: ${err.code}`);

    if (err.code === 'ENOTFOUND' || err.code === 'EAI_FAIL') {
      log(`Retrying ${hostname} without IP family restriction...`);

      const fallbackSocket = netConnect({
        host: hostname,
        port: serverPort
      }, () => {
        log(`Fallback connection successful to ${hostname}`);
        trackConnection(fallbackSocket, `HTTPS-FALLBACK-${hostname}`);
        logDownload(fallbackSocket, tunnelDesc);

        clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (head && head.length > 0) {
          fallbackSocket.write(head);
        }
        fallbackSocket.pipe(clientSocket);
        clientSocket.pipe(fallbackSocket);
      });

      fallbackSocket.on('error', (fallbackErr: NodeJS.ErrnoException) => {
        logErr(`Fallback connection failed for ${hostname}: ${fallbackErr.code}`);
        clientSocket.end('HTTP/1.1 502 Bad Gateway\r\n\r\nConnection Failed');
      });

      fallbackSocket.setTimeout(10000, () => {
        log(`Fallback socket timeout for: ${hostname}`);
        fallbackSocket.destroy();
        clientSocket.end();
      });
    } else {
      clientSocket.end('HTTP/1.1 502 Bad Gateway\r\n\r\nConnection Failed');
    }
  });

  clientSocket.on('error', (err: NodeJS.ErrnoException) => {
    logErr(`Client socket error: ${err.code}`);
    serverSocket.destroy();
  });

  serverSocket.setTimeout(10000, () => {
    log(`Socket timeout for: ${hostname}`);
    serverSocket.destroy();
    clientSocket.end();
  });
});

proxyServer.on('error', (err: Error) => {
  logErr(`Proxy server error: ${err.message}`);
});

// --- Startup ---
async function startServers(): Promise<void> {
  authServer.listen(AUTHPORT, () => {
    log(`Auth server running on port ${AUTHPORT}`);
    
    proxyServer.listen(PORT, () => {
      log(`Proxy server running on port ${PORT}`);
      log('Supports both HTTP and HTTPS traffic');
      log('Using IPv4 preference with IPv6 fallback');
      log('Strict PIN authentication required for all proxy access');
    });
  });
  
  // Test Telegram connectivity
  await testTelegramConnectivity();
}

startServers().catch(err => {
  logErr(`Failed to start servers: ${err.message}`);
  process.exit(1);
});

// --- Graceful Shutdown ---
function shutdown(): void {
  if (isShuttingDown) return;
  isShuttingDown = true;
  log('\nShutting down servers...');
  log(`Active connections: ${activeConnections.size}`);

  clearInterval(cleanupTimer);

  authServer.close(() => {
    log('Auth server stopped accepting new connections');
  });

  proxyServer.close(() => {
    log('Proxy server stopped accepting new connections');
  });

  setTimeout(() => {
    if (activeConnections.size > 0) {
      log(`Force closing ${activeConnections.size} remaining connections...`);
      destroyAllConnections();
    }
    log('Servers fully shut down');
    process.exit(0);
  }, 3000);

  setTimeout(() => {
    log('Forcing shutdown...');
    destroyAllConnections();
    process.exit(0);
  }, 10000);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

process.on('uncaughtException', (err: Error) => {
  logErr(`Uncaught Exception: ${err.message}`);
  shutdown();
});

process.on('unhandledRejection', (reason: any, promise: Promise<any>) => {
  logErr(`Unhandled Rejection at: ${promise}, reason: ${reason}`);
  shutdown();
});
