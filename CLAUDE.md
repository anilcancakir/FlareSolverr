# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

FlareSolverr is a proxy server that bypasses Cloudflare and DDoS-GUARD protection using headless browsers. When a request arrives, it launches Chrome/Chromium, navigates to the URL, waits for challenge resolution, and returns HTML + cookies to the client.

**Two driver engines are supported:**
- **nodriver** (default) - Modern async CDP-based driver in `src/nodriver/`
- **undetected-chromedriver** (legacy) - Selenium-based driver in `src/undetected_chromedriver/`

Select via `DRIVER=nodriver` or `DRIVER=undetected-chromedriver` environment variable.

## Build and Run Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Run from source
python src/flaresolverr.py

# Run with Docker
docker compose up -d

# Install test dependencies
pip install -r test-requirements.txt

# Run tests (requires Chrome/Chromium installed)
python -m unittest discover src
```

## Key Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `DRIVER` | nodriver | Browser driver: `nodriver` or `undetected-chromedriver` |
| `LOG_LEVEL` | info | Logging verbosity (debug/info/warning/error) |
| `HEADLESS` | true | Set `false` to see browser window for debugging |
| `PORT` | 8191 | HTTP server port |
| `BROWSER_TIMEOUT` | 40000 | Browser operation timeout in ms |

## Architecture

### Request Flow
1. Client POSTs to `/v1` with `cmd`, `url`, and optional parameters
2. `flaresolverr.py` routes to appropriate service based on `DRIVER` setting
3. Service gets/creates browser session via `sessions.py` or `sessions_nd.py`
4. Browser navigates to URL and polls for challenge completion
5. Response with cookies, HTML, and headers returned to client

### Key Source Files

| File | Purpose |
|------|---------|
| `src/flaresolverr.py` | Entry point, Bottle HTTP server, route handlers |
| `src/flaresolverr_service_nd.py` | nodriver implementation (async) |
| `src/flaresolverr_service.py` | undetected-chromedriver implementation |
| `src/sessions_nd.py` | nodriver session/browser lifecycle |
| `src/sessions.py` | UC session/WebDriver lifecycle |
| `src/utils.py` | Shared utilities, browser detection, config getters |
| `src/dtos.py` | Request/response data transfer objects |
| `src/tests.py` | Integration tests using WebTest |

### Challenge Detection

Both drivers monitor these selectors to detect when challenges are resolved:
- `#cf-challenge-running`, `.ray_id`, `.attack-box` (Cloudflare)
- `#challenge-spinner`, `#turnstile-wrapper` (Turnstile)
- `#cf-please-wait`, `.main-wrapper` (Various Cloudflare states)

## API Commands

All commands are POST requests to `/v1`:

- `sessions.create` - Create persistent browser session
- `sessions.list` - List active session IDs
- `sessions.destroy` - Close a session
- `request.get` - Make GET request through browser
- `request.post` - Make POST request through browser

## Testing

Tests use WebTest framework against real sites. The test file `src/tests_sites.py` contains URLs for different challenge types. Tests require a working Chrome/Chromium installation.

```bash
# Run all tests
python -m unittest discover src

# Run specific test
python -m unittest src.tests.TestFlareSolverr.test_index_endpoint
```
