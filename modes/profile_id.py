#!/usr/bin/env python3
from __future__ import annotations

import re

_PROFILE_ID = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z")


def validate_profile_id(value: object, default: str = "router") -> str:
    text = str(default if value is None else value).strip()
    if not _PROFILE_ID.fullmatch(text) or text in {".", ".."} or ".." in text or "/" in text or "\\" in text:
        raise ValueError("invalid Router VPN profile id")
    return text
