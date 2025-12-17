// proxy.ts
import fs from 'node:fs';
import path from 'node:path';

// --- Load Configuration ---
let config: any;
try {
  const configPath = path.join(__dirname, 'config.json');
  const configData = fs.readFileSync(configPath, 'utf-8');
  config = JSON.parse(configData);
} catch (error) {
  console.error('Failed to load config file, using defaults:', error);
  // Default fallback values
  config = {
  "port": "32000",
  "allowed_ips": "52.16.14.28,52.1.144.*,192.168.1.*,10.0.0.0/24"
  };
}

import { Server, createServer, IncomingMessage, ServerResponse, request as httpRequest } from 'http';
import { request as httpsRequest } from 'https';
import { parse as urlParse, Url } from 'url';
import { connect as netConnect, Socket } from 'net';
import { setDefaultResultOrder } from 'dns';

// Set DNS to prefer IPv4 but fall back to IPv6
setDefaultResultOrder('ipv4first');

// Configuration from environment variables
const PORT = parseInt(config.port);
const ALLOWED_IPS = config.allowed_ips ? process.config.allowed_ips.split(',') : [];

// Track active connections for graceful shutdown
const activeConnections = new Set<Socket>();
let isShuttingDown = false;

// IP matching utility functions
function ipToInt(ip: string): number {
  return ip.split('.').reduce((int, octet) => (int << 8) + parseInt(octet, 10), 0) >>> 0;
}

interface IPRange {
  start: number;
  end: number;
}

function cidrToRange(cidr: string): IPRange {
  const [network, bits = '32'] = cidr.split('/');
  const bitCount = parseInt(bits, 10);
  const mask = ~((1 << (32 - bitCount)) - 1);
  const networkInt = ipToInt(network);
  const start = networkInt & mask;
  const end = start + (1 << (32 - bitCount)) - 1;
  return { start, end };
}

function matchesWildcard(pattern: string, ip: string): boolean {
  const regexPattern = pattern.replace(/\./g, '\\.').replace(/\*/g, '[0-9]+');
  const regex = new RegExp(`^${regexPattern}$`);
  return regex.test(ip);
}

function matchesCidr(cidr: string, ip: string): boolean {
  try {
    const ipInt = ipToInt(ip);
    const range = cidrToRange(cidr);
    return ipInt >= range.start && ipInt <= range.end;
  } catch (err) {
    return false;
  }
}

function isIPAllowed(clientIP: string): boolean {
  if (ALLOWED_IPS.length === 0) return true; // No restrictions if no ACL

  return ALLOWED_IPS.some(pattern => {
    if (pattern.includes('*')) {
      return matchesWildcard(pattern, clientIP);
    } else if (pattern.includes('/')) {
      return matchesCidr(pattern, clientIP);
    } else {
      return pattern === clientIP;
    }
  });
}

function getClientIP(req: IncomingMessage): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded && typeof forwarded === 'string') {
    return forwarded.split(',')[0].trim();
  }
  return req.socket.remoteAddress?.replace(/^::ffff:/, '') || 'unknown';
}

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
      console.log(`Connection closed: ${connectionId} (${activeConnections.size} remaining)`);
    }
  };

  socket.on('close', cleanup);
  socket.on('error', cleanup);
  socket.on('end', cleanup);

  console.log(`New connection: ${connectionId} (${activeConnections.size} total)`);
}

function destroyAllConnections(): void {
  console.log(`\nForcefully closing ${activeConnections.size} active connections...`);

  activeConnections.forEach(socket => {
    try {
      socket.destroy();
    } catch (err) {
      // Ignore errors during destruction
    }
  });

  activeConnections.clear();
}

// Remove hop-by-hop headers
function removeHopByHopHeaders(headers: { [key: string]: string | string[] | undefined }): void {
  const hopByHopHeaders = [
    'connection', 'keep-alive', 'proxy-authenticate',
    'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade'
  ];

  hopByHopHeaders.forEach(header => {
    delete headers[header];
  });
}

// Create HTTP proxy server
const proxy: Server = createServer();

proxy.on('request', (clientReq: IncomingMessage, clientRes: ServerResponse) => {
  const clientIP = getClientIP(clientReq);

  if (!isIPAllowed(clientIP)) {
    console.log(`Blocked HTTP request from unauthorized IP: ${clientIP}`);
    clientRes.writeHead(403, { 'Content-Type': 'text/plain' });
    clientRes.end('Access denied: Your IP is not allowed to use this proxy');
    return;
  }

  console.log(`Proxying HTTP request from ${clientIP}: ${clientReq.method} ${clientReq.url}`);

  const parsedUrl: Url = urlParse(clientReq.url || '');

  const options = {
    hostname: parsedUrl.hostname || '',
    port: parsedUrl.port || 80,
    path: parsedUrl.path || '',
    method: clientReq.method,
    headers: { ...clientReq.headers },
    family: 4
  };

  options.headers.host = parsedUrl.host || '';
  delete options.headers['proxy-connection'];
  delete options.headers['connection'];
  delete options.headers['keep-alive'];

  // Track client connection
  trackConnection(clientReq.socket, `HTTP-${clientIP}`);
  trackConnection(clientRes.socket, `HTTP-RES-${clientIP}`);

  const proxyReq = httpRequest(options, (proxyRes: IncomingMessage) => {
    removeHopByHopHeaders(proxyRes.headers);
    clientRes.writeHead(proxyRes.statusCode || 500, proxyRes.headers);
    proxyRes.pipe(clientRes);
  });

  // Track proxy request socket
  proxyReq.on('socket', (socket: Socket) => {
    trackConnection(socket, `HTTP-PROXY-${parsedUrl.hostname}`);
  });

  proxyReq.on('error', (err: NodeJS.ErrnoException) => {
    console.error('Proxy request error for', parsedUrl.hostname, ':', err.code);

    if (err.code === 'ENOTFOUND' || err.code === 'EAI_FAIL') {
      console.log('Retrying without IP family restriction...');
      const fallbackOptions = { ...options };
      delete (fallbackOptions as any).family;

      const fallbackReq = httpRequest(fallbackOptions, (fallbackRes: IncomingMessage) => {
        removeHopByHopHeaders(fallbackRes.headers);
        clientRes.writeHead(fallbackRes.statusCode || 500, fallbackRes.headers);
        fallbackRes.pipe(clientRes);
      });

      fallbackReq.on('socket', (socket: Socket) => {
        trackConnection(socket, `HTTP-FALLBACK-${parsedUrl.hostname}`);
      });

      fallbackReq.on('error', (fallbackErr: NodeJS.ErrnoException) => {
        console.error('Fallback request also failed:', fallbackErr.code);
        clientRes.writeHead(500);
        clientRes.end('Proxy error: ' + fallbackErr.message);
      });

      clientReq.pipe(fallbackReq);
    } else {
      clientRes.writeHead(500);
      clientRes.end('Proxy error: ' + err.message);
    }
  });

  proxyReq.setTimeout(10000, () => {
    console.log('HTTP request timeout for:', parsedUrl.hostname);
    proxyReq.destroy();
    clientRes.writeHead(504);
    clientRes.end('Gateway Timeout');
  });

  clientReq.pipe(proxyReq);
});

// Handle CONNECT method for HTTPS tunneling
proxy.on('connect', (clientReq: IncomingMessage, clientSocket: Socket, head: Buffer) => {
  const clientIP = getClientIP(clientReq);

  if (!isIPAllowed(clientIP)) {
    console.log(`Blocked HTTPS request from unauthorized IP: ${clientIP}`);
    clientSocket.end('HTTP/1.1 403 Forbidden\r\n\r\nAccess denied: Your IP is not allowed to use this proxy');
    return;
  }

  console.log(`Proxying HTTPS request from ${clientIP}: CONNECT ${clientReq.url}`);

  const [hostname, port] = (clientReq.url || '').split(':');
  const serverPort = parseInt(port) || 443;

  // Track client socket
  trackConnection(clientSocket, `HTTPS-CLIENT-${clientIP}`);

  const serverSocket = netConnect({
    host: hostname || '',
    port: serverPort,
    family: 4
  }, () => {
    console.log(`Successfully connected to ${hostname}:${serverPort} for client ${clientIP}`);

    // Track server socket
    trackConnection(serverSocket, `HTTPS-SERVER-${hostname}`);

    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    serverSocket.write(head);
    serverSocket.pipe(clientSocket);
    clientSocket.pipe(serverSocket);
  });

  serverSocket.on('error', (err: NodeJS.ErrnoException) => {
    console.error(`Server socket error for ${hostname}:`, err.code);

    if (err.code === 'ENOTFOUND' || err.code === 'EAI_FAIL') {
      console.log(`Retrying ${hostname} without IP family restriction...`);

      const fallbackSocket = netConnect({
        host: hostname || '',
        port: serverPort
      }, () => {
        console.log(`Fallback connection successful to ${hostname}`);

        // Track fallback socket
        trackConnection(fallbackSocket, `HTTPS-FALLBACK-${hostname}`);

        clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        fallbackSocket.write(head);
        fallbackSocket.pipe(clientSocket);
        clientSocket.pipe(fallbackSocket);
      });

      fallbackSocket.on('error', (fallbackErr: NodeJS.ErrnoException) => {
        console.error(`Fallback connection failed for ${hostname}:`, fallbackErr.code);
        clientSocket.end('HTTP/1.1 500 Connection Failed\r\n\r\n');
      });

      fallbackSocket.setTimeout(10000, () => {
        console.log(`Fallback socket timeout for: ${hostname}`);
        fallbackSocket.destroy();
        clientSocket.end();
      });
    } else {
      clientSocket.end('HTTP/1.1 500 Connection Failed\r\n\r\n');
    }
  });

  clientSocket.on('error', (err: NodeJS.ErrnoException) => {
    console.error('Client socket error:', err.code);
    serverSocket.end();
  });

  serverSocket.setTimeout(10000, () => {
    console.log(`Socket timeout for: ${hostname}`);
    serverSocket.destroy();
    clientSocket.end();
  });
});

proxy.on('error', (err: Error) => {
  console.error('Proxy server error:', err);
});

// Start the proxy server
proxy.listen(PORT, () => {
  console.log(`Anonymous HTTP/HTTPS proxy server running on port ${PORT}`);
  console.log('Supports both HTTP and HTTPS traffic');
  console.log('Using IPv4 preference with IPv6 fallback');

  if (ALLOWED_IPS.length > 0) {
    console.log('Access Control List enabled:');
    ALLOWED_IPS.forEach(ip => console.log(`  - ${ip}`));
  } else {
    console.log('No ACL restrictions - proxy is open to all IPs');
  }
});

// Graceful shutdown with timeout
function shutdown(): void {
  if (isShuttingDown) return;

  isShuttingDown = true;
  console.log('\nShutting down proxy server...');
  console.log(`Active connections: ${activeConnections.size}`);

  // Stop accepting new connections
  proxy.close(() => {
    console.log('Proxy server stopped accepting new connections');
  });

  // Give connections 3 seconds to close gracefully
  setTimeout(() => {
    if (activeConnections.size > 0) {
      console.log(`Force closing ${activeConnections.size} remaining connections...`);
      destroyAllConnections();
    }

    console.log('Proxy server fully shut down');
    process.exit(0);
  }, 3000);

  // Force shutdown after 10 seconds max
  setTimeout(() => {
    console.log('Forcing shutdown...');
    destroyAllConnections();
    process.exit(0);
  }, 10000);
}

// Handle shutdown signals
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

// Handle uncaught exceptions
process.on('uncaughtException', (err: Error) => {
  console.error('Uncaught Exception:', err);
  shutdown();
});

process.on('unhandledRejection', (reason: any, promise: Promise<any>) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  shutdown();
});
