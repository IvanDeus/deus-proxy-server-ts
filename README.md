# deus proxy server
A Bun-based anonymous HTTP/HTTPS proxy server that provides secure and flexible proxy capabilities with IP-based access control.

## Features

- Supports both HTTP and HTTPS traffic
- No traffic decryption 
- Anonymous proxy functionality
- IP-based access control through configurable whitelist
- Easy configuration via environment variables
- Lightweight and fast

## Requirements

- Bun 1.3.2 or higher

## Installation

1. Install bun environment into your home dir (if needed):
   ```bash
   curl -fsSL https://bun.sh/install | bash
   ```

2. Clone the repository:
   ```bash
   git clone <repository-url>
   cd deus-proxy-server-ts
   ```

## Configuration

Copy dotenv-example .env:
```
cp dotenv-example .env
```

## Usage

Start the proxy server:

```bash
bun run proxy.ts
```

The proxy server will start on the configured port and only accept connections from the specified allowed IP addresses.

## Production Mode with PM2
For production deployment, use PM2 to manage the proxy server.
   
1. Start the proxy server with PM2 using custom ecosystem file:
   
   ```
   pm2 start proxy.ts --name deus-proxy
   ```
   
2. Manage your proxy server using:
   
   ```
   # View process status
   pm2 status
   
   # View logs
   pm2 logs deus-proxy
   
   # Stop the proxy server
   pm2 stop deus-proxy
   
   # Start the proxy server
   pm2 start deus-proxy   

   # Restart the proxy server
   pm2 restart deus-proxy
   
   ```
3. Go to URL and enter PIN to allow proxy access 
   
## PM2 Process Management
```
# Save the current PM2 configuration
pm2 save

# Start PM2 on system boot
pm2 startup

# Monitor the proxy server
pm2 monit
```

2026 [ ivan deus ]
