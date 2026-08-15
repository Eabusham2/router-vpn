#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
CUSTOM_IMAGES = {
    "init": 3,
    "agent": 1,
    "wireguard": 1,
    "awg2": 1,
    "rosenpass": 1,
    "naive": 1,
    "ss-v2ray": 1,
    "aux": 1,
}
IMAGE_RE = re.compile(
    r"(ghcr\.io/eabusham2/router-vpn-(?:init|agent|wireguard|awg2|rosenpass|naive|ss-v2ray|aux):)"
    r"([0-9a-f]{40})"
)
BROKER_RE = re.compile(
    r"(?m)^(\s*ROUTER_VPN_GITHUB_SHA:\s*)([0-9a-f]{40})(\s*)$"
)


def fail(message: str) -> "NoReturn":
    raise SystemExit(message)


def validate_template(text: str) -> str:
    if re.search(r"(?m)^\s*build:\s*$", text):
        fail("production template must stay image-only")
    if re.search(r"(?m)^\s*context:\s*https?://", text):
        fail("production template may not use a remote Git build context")
    if re.search(r"(?m)^\s*image:\s*\S+:latest\s*$", text):
        fail("production template may not use floating latest images")

    found: list[str] = []
    for image, expected in CUSTOM_IMAGES.items():
        matches = re.findall(
            rf"ghcr\.io/eabusham2/router-vpn-{re.escape(image)}:([0-9a-f]{{40}})",
            text,
        )
        if len(matches) != expected:
            fail(
                f"expected {expected} exact-SHA template references for "
                f"router-vpn-{image}, found {len(matches)}"
            )
        found.extend(matches)

    if not found or len(set(found)) != 1:
        fail("production template custom images must share one exact baseline SHA")

    broker = BROKER_RE.search(text)
    if not broker:
        fail("production template broker provenance is not a full SHA")
    if broker.group(2) != found[0]:
        fail("production template broker SHA does not match custom image SHA")
    return found[0]


def materialize(text: str, target_sha: str) -> str:
    if not SHA_RE.fullmatch(target_sha):
        fail("--sha must be one lowercase 40-character hexadecimal commit SHA")
    baseline = validate_template(text)
    out, image_replacements = IMAGE_RE.subn(
        lambda match: match.group(1) + target_sha,
        text,
    )
    out, broker_replacements = BROKER_RE.subn(
        lambda match: match.group(1) + target_sha + match.group(3),
        out,
    )
    expected_image_replacements = sum(CUSTOM_IMAGES.values())
    if image_replacements != expected_image_replacements:
        fail(
            f"expected {expected_image_replacements} custom image replacements, "
            f"made {image_replacements}"
        )
    if broker_replacements != 1:
        fail(f"expected one broker SHA replacement, made {broker_replacements}")

    validate_template(out)
    remaining = set(IMAGE_RE.findall(out))
    if any(sha != target_sha for _, sha in remaining):
        fail("materialized compose contains a non-target custom image SHA")
    broker = BROKER_RE.search(out)
    if not broker or broker.group(2) != target_sha:
        fail("materialized compose broker provenance does not equal target SHA")

    header = (
        f"# GENERATED exact-SHA Router VPN production compose: {target_sha}\n"
        f"# Source template baseline SHA: {baseline}\n"
        "# Do not commit this generated file over server/portainer-current.yaml.\n"
    )
    return header + out


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Materialize server/portainer-current.yaml for one exact release commit."
    )
    parser.add_argument("--sha", required=True)
    parser.add_argument(
        "--input", default="server/portainer-current.yaml", dest="input_path"
    )
    parser.add_argument("--output", required=True, dest="output_path")
    args = parser.parse_args()

    source = Path(args.input_path)
    output = Path(args.output_path)
    text = source.read_text(encoding="utf-8")
    rendered = materialize(text, args.sha)

    output.parent.mkdir(parents=True, exist_ok=True)
    tmp = output.with_suffix(output.suffix + ".tmp")
    tmp.write_text(rendered, encoding="utf-8")
    tmp.replace(output)
    print(f"Materialized {output} for exact release SHA {args.sha}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
