# Security

- The repository is intentionally public. Keep **secrets and generated private state out of Git**, not the source repository itself.
- Never commit or publish generated private router/node bundles, WireGuard/private protocol keys, passwords, API tokens, pairing codes, cookies, external-profile credentials, provisioning profiles, signing keys, or private runtime configuration.
- Generic installers/Portable packages must remain secret-free. Link/import/pair private nodes separately after installation; public node/profile/status APIs expose only redacted views.
- Never WAN-expose Router VPN private/admin services such as `1080`, `8786`, `8787`, `14444`, `9443`, SSH, Portainer, or AdGuard administration. Other internal/reserved ports remain protected according to the current router-agent/forwarding policy.
- Public listeners are limited to the documented Router VPN protocol/ACME listeners in `docs/CURRENT-GUIDE.md`; external TCP `80` maps to internal `18080` for ACME.
- Use Protected DMZ/forwarding only through the authenticated Router VPN policy path and preserve the reserved-management-port exclusions.
- `Connected` requires exact selected-node/private-path proof or exact expected-public-exit proof. Generic Internet reachability must never be treated as VPN proof.
- Unsupported platform/protocol graphs fail closed; UI/CSS must never force Ready/Connected.
- Rotate/revoke a private node bundle or external credential if it is exposed to an untrusted device/person.
- Physical leak-negative, DNS/IPv4/IPv6, reconnect/network-change and off-LAN tests remain required before final release claims.
