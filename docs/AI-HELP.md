# Router VPN AI Help

Router VPN Setup Center can use a server-side OpenAI provider for contextual troubleshooting. AI Help is optional and fails closed when it is not configured.

## Security model

- The browser never receives the provider API key.
- Provider access is performed only by the authenticated Setup Center server process.
- The key lives at `/opt/router-vpn/config/openai-api.key` with mode `0600` or stricter.
- The model name lives at `/opt/router-vpn/config/openai-model` with mode `0600` or stricter.
- Symlinked, non-regular, group/world-accessible, oversized, or malformed configuration files are rejected.
- Requests are bounded for body, question, context, response size, output tokens, concurrency, timeout, and per-client rate.
- Runtime context is allowlisted by the Setup Center wrapper and provider-side secret fields are redacted again before transmission.
- Requests set `store: false` in the OpenAI Responses API request.
- AI Help never replaces Router VPN path proof, mode health checks, forwarding state, Connected Clients, or native-device tests. It explains and troubleshoots the real state those systems report.

## Configure locally

On the Router VPN host, run:

```sh
/src/server/scripts/configure-ai-help.sh configure MODEL_NAME
```

The script asks for the API key with terminal echo disabled. It refuses non-interactive stdin for the key so a secret is not casually piped or placed into shell history. It writes temporary private files under `/opt/router-vpn/config`, sets mode `0600`, and atomically renames them into place.

Check only non-secret status:

```sh
/src/server/scripts/configure-ai-help.sh status
```

Disable and remove the private provider configuration:

```sh
/src/server/scripts/configure-ai-help.sh disable
```

If Setup Center is already running, restart/recreate only that process/container after changing provider configuration. Do not place the API key in Compose, browser JavaScript, a URL, a command-line argument, or a public download artifact.

## Setup Center behavior

The `AI Help` panel is injected into the existing authenticated Setup Center page. Its endpoints are same-origin:

- `GET /api/ai-help/status`
- `POST /api/ai-help`

Both reuse the existing Setup Center authentication boundary. If the provider is not configured, Setup Center remains fully operational and the AI Help control reports unavailable rather than preventing startup.
