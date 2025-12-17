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

Create a `config.json` file in the root directory with the following variables. Choose proxy server port and allowed IPs to access proxy:

```
{
  "port": "8080",
  "allowed_ips": "52.167.144.238,52.167.144.*,192.168.1.*,10.0.0.0/24" 
}
```

### Configuration Options

- `PORT`: The port number on which the proxy server will listen (default: 33000)
- `ALLOWED_IPS`: Comma-separated list of IP addresses or IP ranges that are allowed to use the proxy. Supports:
  - Individual IPs: `192.168.1.100`
  - IP wildcards: `192.168.1.*`
  - CIDR notation: `10.0.0.0/24`

## Usage

Start the proxy server:

```bash
bun run proxy.ts
```

The proxy server will start on the configured port and only accept connections from the specified allowed IP addresses.

## Production Mode with PM2
For production deployment, use PM2 to manage the proxy server.

1. Create ecosystem.config.js:
   
   ```
   // ecosystem.config.js
   module.exports = {
     apps: [{
       name: 'deus-proxy',
       script: '/var/proxy.ts',
       interpreter: '/home/.bun/bin/bun',
       interpreter_args: 'run',
       exec_mode: 'fork',
       instances: 1,
       autorestart: true,
       watch: false,
       env: {
         NODE_ENV: 'production',
         PORT: 33000,
         ALLOWED_IPS: '5.7.7.7'
       }
     }]
   };
   ```
   
3. Start the proxy server with PM2 using custom ecosystem file:
   
   ```
   pm2 start ecosystem.config.js
   ```
   
5. Manage your proxy server using:
   
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
## PM2 Process Management
```
# Save the current PM2 configuration
pm2 save

# Start PM2 on system boot
pm2 startup

# Monitor the proxy server
pm2 monit
```

2025 [ivan deus]
