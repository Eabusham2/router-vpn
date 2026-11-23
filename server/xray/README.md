# Xray service

The Portainer stack runs the pinned, source-built Xray runtime shipped in the
exact-commit `router-vpn-init` image. The `xray-pq` service invokes
`/usr/local/bin/xray` with the generated
`/opt/router-vpn/config/xray/server.json` configuration.

Deploy it as part of the complete Router VPN stack using the
[Portainer installation guide](../../docs/INSTALL-PORTAINER.md). The generated
configuration belongs to the server's private state; it is not a public example
to copy between installations. Use the Setup Center and supported environment
settings to manage listeners and profiles.

For transport choices and ports, see the [mode reference](../../docs/MODES.md)
and [user guide](../../docs/CURRENT-GUIDE.md). Image publication and production
deployment must follow the [same-commit release procedure](../../docs/PRODUCTION-RELEASE.md).
