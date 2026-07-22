# deus proxy server

A Bun-based anonymous HTTP/HTTPS proxy server that provides secure and flexible proxy capabilities with dynamic PIN-based IP access control and built-in brute-force protection.

## Features

- Supports both HTTP and HTTPS traffic (CONNECT tunneling)
- No traffic decryption (end-to-end encryption preserved for HTTPS)
- Anonymous proxy functionality
- **Dynamic IP-based access control via PIN authentication**
- **Built-in brute-force defense** (2200ms delay on all authentication attempts to prevent timing attacks and rate abuse)
- Automatic IP authorization expiration and background cleanup
- Easy configuration via environment variables
- Lightweight, fast, and IPv4/IPv6 fallback support
- Graceful shutdown handling with active connection tracking

## Requirements

- Bun 1.3.2 or higher

## Installation

1. Install the Bun environment into your home directory (if needed):
   ```bash
   curl -fsSL https://bun.sh/install | bash
   ```

2. Clone the repository:
   ```bash
   git clone <repository-url>
   cd deus-proxy-server-ts
   ```

## Configuration

Copy the example environment file to create your local configuration:
```bash
cp dotenv-example .env
```

Edit the `.env` file to configure the server. Available variables:
- `PORT`: Proxy server port (default: `32000`)
- `AUTHPORT`: Authentication web interface port (default: `32001`)
- `PIN`: The secret PIN required to authorize an IP address (default: `0000`)
- `TIMEOUT`: Duration in **minutes** before an authorized IP expires (default: `300`)

## Usage

1. Start the proxy server:
   ```bash
   bun run proxy.ts
   ```

2. **Authorize your IP**: Open your browser and navigate to the authentication port (e.g., `http://<your-server-ip>:32001`).

3. Enter the configured `PIN`. Upon success, your current IP address will be whitelisted for the duration specified in `TIMEOUT`.

4. **Use the Proxy**: Configure your device, browser, or application to route traffic through the proxy port (e.g., `<your-server-ip>:32000`). 

*(Note: Unauthorized IPs attempting to use the proxy port will receive a `403 Access denied` response.)*

## Production Mode with PM2

For production deployment, use PM2 to manage the proxy server and ensure it stays running.

1. Start the proxy server with PM2:
   ```bash
   pm2 start proxy.ts --name deus-proxy
   ```

2. Manage your proxy server using PM2 commands:
   ```bash
   # View process status
   pm2 status
   
   # View real-time logs
   pm2 logs deus-proxy
   
   # Stop the proxy server
   pm2 stop deus-proxy
   
   # Start the proxy server
   pm2 start deus-proxy
   
   # Restart the proxy server
   pm2 restart deus-proxy
   ```

## PM2 Process Management

```bash
# Save the current PM2 process list to respawn on reboot
pm2 save

# Configure PM2 to start on system boot
pm2 startup

# Monitor resource usage and logs in real-time
pm2 monit
```

---
2026 [ ivan deus ]
