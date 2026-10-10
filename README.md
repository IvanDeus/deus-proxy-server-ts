# deus proxy server

A Bun-based anonymous HTTP/HTTPS proxy server that provides secure and flexible proxy capabilities with **Telegram Bot-based temporary PIN access control** and built-in brute-force protection.

## Features

- Supports both HTTP and HTTPS traffic (CONNECT tunneling)
- No traffic decryption (end-to-end encryption preserved for HTTPS)
- Anonymous proxy functionality
- **Dynamic 5-digit PINs delivered via Telegram Bot** (2-minute validity, single-use)
- **Built-in brute-force defense** (2200ms delay on all authentication attempts to prevent timing attacks and rate abuse)
- Automatic IP authorization expiration and background cleanup
- **Per-request traffic accounting** (downloaded megabytes logged for every request and tunnel)
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
   git clone https://github.com/IvanDeus/deus-proxy-server-ts.git
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
- `TELEGRAM_BOT_TOKEN`: Your Telegram Bot API token (required)
- `CHANNEL_ID`: Telegram channel ID where PINs will be sent (required)
- `TIMEOUT`: Duration in **minutes** before an authorized IP expires (default: `300`)
- `LOG_TZ`: IANA time zone used for the timestamp prefix on log lines (default: `UTC`, e.g. `Europe/Moscow`)

**Important**: You must set up a Telegram Bot and get its token from [@BotFather](https://t.me/botfather). The bot must be added as an administrator to the channel where you want to receive PINs.

## Usage

1. Start the proxy server:
   ```bash
   bun run proxy.ts
   ```

2. **Get your PIN**: Open your browser and navigate to the authentication port (e.g., `http://<your-server-ip>:32001`).

3. Click **"📱 Get PIN via Telegram"** button. You'll receive a 5-digit PIN in your Telegram channel within seconds. The PIN input field will appear below the button.

4. **Enter the PIN** in the field that appears below the button. The PIN is valid for **2 minutes** and will be consumed after successful use.

5. **Use the Proxy**: Configure your device, browser, or application to route traffic through the proxy port (e.g., `<your-server-ip>:32000`). 

*(Note: Unauthorized IPs attempting to use the proxy port will receive a `403 Access denied` response.)*

## Logging

Everything is written to stdout/stderr, so a process manager like PM2 collects it. Each line is
prefixed with `[day.month.year hour:minute:second]` in the zone given by `LOG_TZ`.

```
[09.10.2026 09:14:38] Proxying HTTPS request from 203.0.113.7: CONNECT example.com:443
[09.10.2026 09:14:39] Downloaded 12.34 MB (12910848 bytes) for CONNECT example.com:443 for 203.0.113.7
[09.10.2026 09:14:41] [ERROR] Server socket error for example.com: ECONNRESET
```

The `Downloaded` line reports what the upstream sent for one HTTP response or one CONNECT tunnel. It
is written once the stream finishes, so an aborted transfer still logs the bytes it managed to pull.

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
