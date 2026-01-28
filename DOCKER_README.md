# FlareSolverr

Proxy server to bypass Cloudflare and DDoS-GUARD protection using a headless browser (nodriver).

## Quick Start

```bash
docker run -d \
  --name=flaresolverr \
  -p 8191:8191 \
  -e LOG_LEVEL=info \
  --restart unless-stopped \
  anilcancakir/flaresolverr:latest
```

## Docker Compose

```yaml
services:
  flaresolverr:
    image: anilcancakir/flaresolverr:latest
    container_name: flaresolverr
    ports:
      - "8191:8191"
    environment:
      - LOG_LEVEL=info
      - TZ=Europe/Istanbul
    restart: unless-stopped
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `info` | Verbosity: `debug`, `info`, `warning`, `error` |
| `HEADLESS` | `true` | Run browser in headless mode |
| `BROWSER_TIMEOUT` | `40000` | Browser timeout in milliseconds |
| `TZ` | `UTC` | Timezone (e.g., `Europe/Istanbul`) |
| `PORT` | `8191` | Server listening port |

## Usage Examples

### GET Request
```bash
curl -X POST http://localhost:8191/v1 \
  -H "Content-Type: application/json" \
  -d '{"cmd":"request.get","url":"https://example.com","maxTimeout":60000}'
```

### POST with Form Data
```bash
curl -X POST http://localhost:8191/v1 \
  -H "Content-Type: application/json" \
  -d '{"cmd":"request.post","url":"https://example.com/login","postData":"user=test&pass=123"}'
```

### POST with JSON Data
```bash
curl -X POST http://localhost:8191/v1 \
  -H "Content-Type: application/json" \
  -d '{"cmd":"request.post","url":"https://api.example.com","postData":{"key":"value"}}'
```

### With Proxy
```bash
curl -X POST http://localhost:8191/v1 \
  -H "Content-Type: application/json" \
  -d '{"cmd":"request.get","url":"https://example.com","proxy":{"url":"http://proxy:8080"}}'
```

## API Commands

| Command | Description |
|---------|-------------|
| `request.get` | Fetch URL via GET |
| `request.post` | Send POST request (form or JSON) |
| `sessions.create` | Create persistent browser session |
| `sessions.list` | List active sessions |
| `sessions.destroy` | Close a session |

## Features

- Cloudflare bypass with nodriver (async CDP)
- JSON and form-urlencoded POST support
- Custom HTTP headers
- Proxy support
- Session management
- Response headers capture

## Links

- [GitHub Repository](https://github.com/anilcancakir/FlareSolverr)
- [Documentation](https://github.com/anilcancakir/FlareSolverr#readme)
- [Changelog](https://github.com/anilcancakir/FlareSolverr/blob/main/CHANGELOG.md)

## Credits

Based on [FlareSolverr](https://github.com/FlareSolverr/FlareSolverr) and [21hsmw's nodriver fork](https://github.com/21hsmw/FlareSolverr).
