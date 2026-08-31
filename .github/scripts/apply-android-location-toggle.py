#!/usr/bin/env python3
from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REL = "android/app/src/main/java/com/eabusham/routervpn/RouterVpnNodeMapView.java"
PATH = ROOT / REL


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=ROOT, text=True, check=check)


def commit(paths: list[str], message: str) -> None:
    run("git", "add", "-A", "--", *paths)
    status = run("git", "diff", "--cached", "--quiet", check=False)
    if status.returncode == 0:
        return
    if status.returncode != 1:
        raise SystemExit(f"git diff failed: {status.returncode}")
    run("git", "commit", "-m", message)


def replace_once_or_verify(text: str, old: str, new: str, label: str) -> str:
    old_count = text.count(old)
    new_count = text.count(new)
    if old_count == 1 and new_count == 0:
        return text.replace(old, new, 1)
    if old_count == 0 and new_count == 1:
        return text
    raise SystemExit(f"{label} drift: old={old_count} new={new_count}")


def patch() -> None:
    text = PATH.read_text(encoding="utf-8")
    text = replace_once_or_verify(
        text,
        "    private static final long MAX_LAST_LOCATION_AGE_MS=5*60*1000L;",
        "    private static final long MAX_LAST_LOCATION_AGE_MS=30*1000L;\n    private static final float MAX_LOCATION_ACCURACY_METERS=10_000f;",
        "Android location freshness constants",
    )
    text = replace_once_or_verify(
        text,
        "        if(locationButtonRect(world).contains(event.getX(),event.getY())){enableRealUserLocation();performClick();return true;}",
        "        if(locationButtonRect(world).contains(event.getX(),event.getY())){if(validUserLocation())hideRealUserLocation();else enableRealUserLocation();performClick();return true;}",
        "Android location toggle",
    )
    text = replace_once_or_verify(
        text,
        "    private void acceptRealLocation(Location location){\n        if(location==null||!Double.isFinite(location.getLatitude())||!Double.isFinite(location.getLongitude())||location.getLatitude()<-90||location.getLatitude()>90||location.getLongitude()<-180||location.getLongitude()>180)return;\n        userLocation=new Location(location);locationState=\"LOCATE ME\";invalidate();\n    }",
        "    private void acceptRealLocation(Location location){\n        if(location==null||!Double.isFinite(location.getLatitude())||!Double.isFinite(location.getLongitude())||location.getLatitude()<-90||location.getLatitude()>90||location.getLongitude()<-180||location.getLongitude()>180)return;\n        long age=Math.abs(System.currentTimeMillis()-location.getTime());\n        if(age>MAX_LAST_LOCATION_AGE_MS||(location.hasAccuracy()&&(location.getAccuracy()<0||location.getAccuracy()>MAX_LOCATION_ACCURACY_METERS)))return;\n        userLocation=new Location(location);locationState=\"HIDE ME\";invalidate();\n    }\n\n    private void hideRealUserLocation(){\n        locationRequestPending=false;\n        try{if(locationManager!=null)locationManager.removeUpdates(locationListener);}catch(SecurityException ignored){}\n        userLocation=null;locationState=\"LOCATE ME\";invalidate();\n    }",
        "Android fresh location adoption",
    )
    text = replace_once_or_verify(
        text,
        "        RectF button=locationButtonRect(world);canvas.drawRoundRect(button,dp(12),dp(12),locationButton);secondary.setTextAlign(Paint.Align.CENTER);String label=validUserLocation()?\"YOU • REFRESH\":locationState;canvas.drawText(label,button.centerX(),button.centerY()+dp(3.5f),secondary);secondary.setTextAlign(Paint.Align.LEFT);",
        "        RectF button=locationButtonRect(world);canvas.drawRoundRect(button,dp(12),dp(12),locationButton);secondary.setTextAlign(Paint.Align.CENTER);String label=validUserLocation()?\"YOU • HIDE\":locationState;canvas.drawText(label,button.centerX(),button.centerY()+dp(3.5f),secondary);secondary.setTextAlign(Paint.Align.LEFT);",
        "Android location button label",
    )
    PATH.write_text(text, encoding="utf-8")
    commit([REL], "Make Android real-location marker fresh and toggleable [skip ci]")


def cleanup() -> None:
    paths = [
        ".github/workflows/one-shot-android-location-toggle.yml",
        ".github/scripts/apply-android-location-toggle.py",
    ]
    for rel in paths:
        path = ROOT / rel
        if path.exists():
            path.unlink()
    commit(paths, "Remove completed Android location automation [skip ci]")


def main() -> int:
    patch()
    run("git", "diff", "--check")
    cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
