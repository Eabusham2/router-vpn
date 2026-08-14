# Router VPN AI Help

Router VPN Setup Center can use an optional **server-side AI Help provider** for contextual troubleshooting. It supports OpenAI, Google Gemini, Anthropic/Claude, DeepSeek, xAI/Grok, Moonshot/Kimi, and a private local OpenAI-compatible AI endpoint on the AI Board. AI Help fails closed when it is not configured and never becomes a dependency for VPN operation.

## Security and grounding model

- The browser never receives a provider API key, provider base URL, Setup Center token, or router-agent admin token.
- Provider access is performed only by the authenticated Setup Center server process.
- Provider-neutral configuration lives under `/opt/router-vpn/config/` in mode `0600` files: `ai-provider`, `ai-model`, optional `ai-api.key`, optional `ai-base-url`, and `ai-web-access`.
- The local provider accepts only an OpenAI-compatible endpoint. Plain HTTP is restricted to loopback/private address space; a public plain-HTTP endpoint is rejected.
- Symlinked, non-regular, group/world-accessible, oversized, or malformed configuration files are rejected.
- Requests are bounded for body, question, context, response size, output tokens, concurrency, timeout, and per-client rate.
- Context is **data, not instructions**. Setup Center supplies only a bounded allow-list of Router VPN documentation, a description of the current Setup Center surface, aggregated Connected Clients state, non-secret server status/capabilities, and the forwarding/LAN policy booleans. Private generated configs, bundles, keys, pairing codes, exact client credentials, cookies, and arbitrary repository paths are not included.
- Provider-side secret fields are redacted again before transmission.
- OpenAI and xAI Responses requests set `store: false`. Other adapters use their stateless request endpoints and do not create application-side conversation history.
- Provider-native web search can be enabled for providers whose current API exposes it (OpenAI, Gemini, Anthropic/Claude, xAI/Grok). DeepSeek, Moonshot/Kimi, and the generic local adapter report web search unavailable unless a future explicitly implemented provider capability is added; Router VPN never labels ordinary model knowledge as live web access.
- AI Help never replaces Router VPN path proof, mode health checks, forwarding state, Connected Clients, kill-switch checks, or native-device tests. It explains and troubleshoots the real state those systems report.

## Configure locally

On the Router VPN host, run:

```sh
/src/server/scripts/configure-ai-help.sh configure PROVIDER MODEL_NAME
```

Examples of `PROVIDER` are `openai`, `gemini`, `anthropic`, `deepseek`, `xai`, `moonshot`, and `local`. Aliases `claude`, `grok`, `kimi`, `google`, and `aiboard` are accepted. The script asks for the API key with terminal echo disabled. For `local`, it also asks for the private AI endpoint and permits an empty key when the local server does not require authentication.

The API key is never accepted as a command-line argument. The script refuses non-interactive stdin for credential entry so a secret is not casually piped or placed into shell history. It writes private files atomically under `/opt/router-vpn/config`.

Control provider-native web access:

```sh
/src/server/scripts/configure-ai-help.sh web on
/src/server/scripts/configure-ai-help.sh web off
```

Check only non-secret status:

```sh
/src/server/scripts/configure-ai-help.sh status
```

Disable and remove the private provider configuration:

```sh
/src/server/scripts/configure-ai-help.sh disable
```

If Setup Center is already running, restart/recreate only that process/container after changing provider configuration. Do not place an API key in Compose, browser JavaScript, a URL, a command-line argument, a client bundle, or a public download artifact.

## Setup Center behavior

The `AI Help` panel is injected into the existing authenticated Setup Center page. Its endpoints are same-origin:

- `GET /api/ai-help/status`
- `POST /api/ai-help`

The status response identifies the selected provider/model and whether provider-native web access is actually enabled. Both routes reuse the existing Setup Center authentication boundary. If the provider is not configured, Setup Center remains fully operational and AI Help reports unavailable rather than preventing startup.
