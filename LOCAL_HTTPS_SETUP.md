# Local HTTPS Development Setup

For local development with HTTPS (needed for secure cookies and service bindings), you have several options:

## Option 1: Cloudflare Tunnel (Recommended)

Use `cloudflared` to create a secure tunnel to your local dev server:

```bash
# Install cloudflared
brew install cloudflare/cloudflare/cloudflared

# Start your API locally (HTTP)
cd hamrah-api
wrangler dev --local --port 8787

# In another terminal, create tunnel to your local API
cloudflared tunnel --url http://localhost:8787
# This will give you an HTTPS URL like: https://abc123.trycloudflare.com
```

## Option 2: Reverse Proxy with mkcert

Set up a local HTTPS proxy using mkcert and a simple proxy:

```bash
# Install mkcert
brew install mkcert
mkcert -install

# Create certificates for local development
mkcert api.hamrah.local hamrah.local localhost 127.0.0.1 ::1

# Create a simple proxy server (proxy-server.js)
```

Create `proxy-server.js`:
```javascript
const https = require('https');
const fs = require('fs');
const httpProxy = require('http-proxy-proxy');

const proxy = httpProxy.createProxyServer({});
const options = {
  key: fs.readFileSync('./api.hamrah.local-key.pem'),
  cert: fs.readFileSync('./api.hamrah.local.pem'),
};

const server = https.createServer(options, (req, res) => {
  // Add CORS headers
  res.setHeader('Access-Control-Allow-Origin', 'https://hamrah.local:5173');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Cookie');

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  proxy.web(req, res, { target: 'http://localhost:8787' });
});

server.listen(8443, () => {
  console.log('HTTPS proxy running on https://api.hamrah.local:8443');
});
```

Then add to your `/etc/hosts`:
```
127.0.0.1   api.hamrah.local
127.0.0.1   hamrah.local
```

Run:
```bash
# Terminal 1: Start API
wrangler dev --local --port 8787

# Terminal 2: Start HTTPS proxy
node proxy-server.js

# Terminal 3: Start web app with HTTPS
cd ../hamrah-app
pnpm dev --host hamrah.local --port 5173 --https
```

## Option 3: Using Wrangler Remote Mode

Use Wrangler's remote mode which provides HTTPS by default:

```bash
# This deploys to Cloudflare but uses preview URLs
wrangler dev
```

This gives you an HTTPS URL like `https://hamrah-api.your-subdomain.workers.dev`

## Option 4: Docker with Traefik (Advanced)

Create a `docker-compose.yml` with Traefik for local HTTPS:

```yaml
version: '3.7'

services:
  traefik:
    image: traefik:v2.10
    command:
      - --api.insecure=true
      - --providers.docker=true
      - --entrypoints.web.address=:80
      - --entrypoints.websecure.address=:443
      - --certificatesresolvers.myresolver.acme.tlschallenge=true
      - --certificatesresolvers.myresolver.acme.caserver=https://acme-staging-v02.api.letsencrypt.org/directory
      - --certificatesresolvers.myresolver.acme.email=your-email@example.com
      - --certificatesresolvers.myresolver.acme.storage=/letsencrypt/acme.json
    ports:
      - "80:80"
      - "443:443"
      - "8080:8080"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - letsencrypt:/letsencrypt

  hamrah-api-proxy:
    image: nginx:alpine
    labels:
      - traefik.enable=true
      - traefik.http.routers.api.rule=Host(`api.hamrah.local`)
      - traefik.http.routers.api.tls=true
      - traefik.http.routers.api.tls.certresolver=myresolver
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
    depends_on:
      - traefik

volumes:
  letsencrypt:
```

## Recommended Development Setup

For the best development experience, use **Option 1 (Cloudflare Tunnel)**:

1. **Terminal 1** - API with Wrangler:
```bash
cd hamrah-api
wrangler dev --local --port 8787
```

2. **Terminal 2** - Cloudflare Tunnel:
```bash
cloudflared tunnel --url http://localhost:8787
# Note the HTTPS URL it provides
```

3. **Terminal 3** - Web App:
```bash
cd hamrah-app
# Update wrangler.jsonc to use the tunnel URL for AUTH_API service binding
pnpm dev
```

4. **Update Service Binding** in `hamrah-app/wrangler.jsonc`:
```json
"services": [
  { 
    "binding": "AUTH_API", 
    "service": "hamrah-api",
    "environment": "development"
  }
]
```

Or for external URL:
```json
"services": [
  { 
    "binding": "AUTH_API", 
    "service": "https://abc123.trycloudflare.com"
  }
]
```

## Environment Variables for Local Development

Add to `hamrah-api/.dev.vars`:
```
INTERNAL_API_KEY=hamrah-internal-dev-key
NODE_ENV=development
DATABASE_URL=sqlite:./dev.db
```

Add to `hamrah-app/.dev.vars`:
```
GOOGLE_CLIENT_SECRET=your-google-secret
APPLE_CERTIFICATE=your-apple-certificate
INTERNAL_API_KEY=hamrah-internal-dev-key
```

## Testing HTTPS Locally

Test that cookies work across domains:

```bash
# Test service binding
curl -X POST https://your-tunnel-url.trycloudflare.com/api/internal/sessions \
  -H "Content-Type: application/json" \
  -H "X-Internal-Service: hamrah-app" \
  -H "X-Internal-Key: hamrah-internal-dev-key" \
  -d '{"user_id":"test-user","platform":"web"}'

# Test cookie setting from web app
curl -X POST https://hamrah.local:5173/api/auth/native \
  -H "Content-Type: application/json" \
  -d '{"provider":"google","credential":"test-token","platform":"web"}'
```

This setup ensures:
- ✅ Secure cookies work locally
- ✅ Service bindings work between workers
- ✅ CORS is properly configured
- ✅ HTTPS is available for all services
- ✅ iOS App Attestation can be tested