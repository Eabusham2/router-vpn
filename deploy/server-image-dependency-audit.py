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
    "ghcr.io/xtls/xray-core:26.7.11",
    "ghcr.io/rosenpass/rosenpass:sha-00569eb",
    "pocat/naiveproxy:v2.11.4",
    "ghcr.io/shadowsocks/ssserver-rust:v1.24.0",
    "ARG OVERTLS_VERSION=0.3.12",
):
    assert required in joined, f"fixed transport dependency missing: {required}"

print("published server image dependency pin audit: OK")
