#!/usr/bin/env python3
"""Source-level dependency pin contract for published Router VPN server images."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]

PUBLISHED = (
    "server/init/Dockerfile",
    "deploy/router-agent.Dockerfile",
    "deploy/update-controller.Dockerfile",
    "server/wireguard/Dockerfile",
    "server/awg2/Dockerfile",
    "server/rosenpass/Dockerfile",
    "server/naive/Dockerfile",
    "server/ss-v2ray/Dockerfile",
    "server/aux-proxies/Dockerfile",
)

docs = {rel: (ROOT / rel).read_text(encoding="utf-8") for rel in PUBLISHED}
joined = "\n".join(docs.values())

for rel, body in docs.items():
    lower = body.lower()
    assert ":latest" not in lower, f"{rel}: floating latest image tag"
    assert "/heads/main" not in lower and "/heads/master" not in lower, f"{rel}: branch archive download"
    assert "archive/main." not in lower and "archive/master." not in lower, f"{rel}: branch archive download"
    assert "git checkout main" not in lower and "git checkout master" not in lower, f"{rel}: branch checkout"

# Language/toolchain builders used by project-owned binaries must name a patch
# release. Registry/image digests from the release workflow remain the evidence
# for the exact built bytes.
for forbidden in (
    "FROM golang:1.24-alpine",
    "FROM rust:1.88-bookworm",
):
    assert forbidden not in joined, f"floating language builder returned: {forbidden}"
for required in (
    "FROM golang:1.24.13-alpine AS build",
    "FROM golang:1.24.13-alpine AS binaries",
    "FROM golang:1.25.12-bookworm AS go-build",
    "FROM golang:1.23.12-alpine AS plugin",
    "FROM rust:1.88.0-bookworm AS overtls-build",
):
    assert required in joined, f"published image dependency pin missing: {required}"

# Every source archive commit parameter in a published Dockerfile is one full
# immutable Git object id.
for rel, body in docs.items():
    for name, value in re.findall(r"(?m)^ARG\s+([A-Z0-9_]*COMMIT)=([^\s]+)\s*$", body):
        assert re.fullmatch(r"[0-9a-f]{40}", value), f"{rel}: {name} is not a full commit: {value}"

for required in (
    "ghcr.io/sagernet/sing-box:v1.13.12",
    "golang:1.26.3-alpine AS xray",
    "ghcr.io/rosenpass/rosenpass:sha-00569eb",
    "pocat/naiveproxy:v2.11.4-uot",
    "ghcr.io/shadowsocks/ssserver-rust:v1.24.0",
    "ARG OVERTLS_VERSION=0.3.12",
):
    assert required in joined, f"fixed transport dependency missing: {required}"

assert "deploy/build-xray-runtime.py" in docs["server/init/Dockerfile"]
assert "COPY --from=xray /xray/linux-${TARGETARCH}/xray" in docs["server/init/Dockerfile"]
assert "50231eaff98ccc31b5cbd247a721c16e97fe5ec1" in (ROOT/"deploy/prepare-xray-runtime.py").read_text()
assert "POLICY.prepare(source)" in (ROOT/"deploy/build-xray-runtime.py").read_text()
agent = docs["deploy/router-agent.Dockerfile"]
for required in (
    "FROM alpine:3.22 AS standalone-tor-build",
    "COPY mobile/torpack/sources.json /src/mobile/torpack/",
    "deploy/apply-tor-padding.py /src/deploy/",
    "mobile/tor/padding-integration.patch mobile/tor/padding-source-lock.json /src/mobile/tor/",
    "python3 /src/deploy/build-server-tor.py --output /tor-package",
    "python3 /src/deploy/test_server_tor_package.py --prefix /tor-package",
    'COPY --from=standalone-tor-build /tor-package/bin/routervpn-tor /usr/local/bin/routervpn-tor',
    'COPY --from=standalone-tor-build /tor-package/share/router-vpn/tor/ /usr/local/share/router-vpn/tor/',
    'COPY --from=relay-core /core/routervpn-server-tor-pt-notices.json /usr/local/share/router-vpn/tor-pt-notices.json',
    'COPY --from=standalone-tor-build /tor-package /server-tor-test',
    'ROUTERVPN_SERVER_TOR_PACKAGE=/server-tor-test CGO_ENABLED=1',
    'go test -mod=mod -tags with_quic,with_wireguard,with_gvisor,with_openvpn,routervpn_native_pq,with_naive_outbound,with_musl',
    "./cmd/sing-box ./routervpn/servertor -run '^TestServerTor' -count=1 -timeout 90s",
    'python3 /usr/local/share/router-vpn/tor/verify.py --prefix /usr/local --platform "linux/${TARGETARCH}" --offline-self-test',
):
    assert required in agent, f"standalone server Tor image gate missing: {required}"
tor_builder = (ROOT / 'deploy/build-server-tor.py').read_text()
assert "PADDING.apply(source['tor'])" in tor_builder
assert "'routervpn_padding/..', 'relaycrypt/..', 'cellqueue/..'" in tor_builder
assert "PADDING.verify(source['tor'])" in tor_builder
preflight = (ROOT / '.github/workflows/arm64-portainer-preflight.yml').read_text()
for required in (
    'docker run --rm --network none --platform linux/arm64',
    '--entrypoint python3 router-vpn-preflight-agent:arm64',
    '/usr/local/share/router-vpn/tor/verify.py --prefix /usr/local',
    '--platform linux/arm64 --offline-self-test',
):
    assert required in preflight, f"installed ARM64 standalone Tor verification missing: {required}"
print("published server image dependency pin audit: OK")
