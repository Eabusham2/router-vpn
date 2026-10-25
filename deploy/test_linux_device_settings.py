#!/usr/bin/env python3
"""Exercise the shipping GTK device form and reject broken ownership guards."""
from __future__ import annotations

import os
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
INCLUDE = ROOT / "client/linux/routervpn-device-settings-v1.inc"
FIXTURE = ROOT / "client/linux/test-device-settings-v1.c"


def run(args, *, broken=False):
    env = dict(os.environ, G_DEBUG="fatal-criticals")
    result = subprocess.run([str(arg) for arg in args], text=True, capture_output=True, timeout=45, env=env)
    if broken:
        if result.returncode == 0 or "GTK device settings check failed:" not in result.stdout + result.stderr:
            raise AssertionError("Broken device guard did not fail its executable assertion:\n" + result.stdout + result.stderr)
    elif result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    elif result.stdout.strip():
        print(result.stdout.strip(), flush=True)


def main():
    source = INCLUDE.read_text(encoding="utf-8")
    build = (ROOT / "client/linux/build-native-app.sh").read_text(encoding="utf-8")
    settings = (ROOT / "client/linux/routervpn-profile-settings-v1.inc").read_text(encoding="utf-8")
    assert 'DEVICE_INC="$ROOT/client/linux/routervpn-device-settings-v1.inc"' in build
    assert '#include "routervpn-device-settings-v1.inc"\\n#include "routervpn-profile-settings-v1.inc"' in build
    assert '"$DNS_INC" "$SHUTDOWN_INC" "$DEVICE_INC"' in build
    callback = settings.split("static void on_profile_settings_v7(", 1)[1]
    assert callback.index("linux_device_settings_open_v1(app)") < callback.index('api_request("/api/profile/settings"')
    variants = {
        "selected-owner": ('if (g_strcmp0(active_router_id(s->app), s->profile) != 0)', 'if (FALSE && g_strcmp0(active_router_id(s->app), s->profile) != 0)'),
        "fresh-idle": ('if (!routervpn_require_mutation_idle(s->app, "saving imported-node device settings"))', 'if (!routervpn_require_mutation_idle(s->app, "saving imported-node device settings") && FALSE)'),
        "unsupported-save": ('if (!s->supported || !s->idle)', 'if (!s->idle)'),
        "fixed-mtu-bounds": ('return *value >= 1280 && *value <= 9000;', 'return TRUE;'),
        "auto-mtu-reset": ('gint64 manual = 0;', 'gint64 manual = 1420;'),
        "captured-token": ('g_strcmp0(kind, "external") != 0 || !linux_device_token_v1(token)', 'g_strcmp0(kind, "external") != 0 || (FALSE && !linux_device_token_v1(token))'),
        "unchanged-startup": ('if (g_strcmp0(startup, s->initial_startup) != 0 || automatic != s->initial_automatic)', 'if (TRUE || g_strcmp0(startup, s->initial_startup) != 0 || automatic != s->initial_automatic)'),
        "captured-policy-note": ('const char *note = linux_device_string_v1(captured, "note");', 'const char *note = NULL;'),
    }
    flags = shlex.split(subprocess.check_output(["pkg-config", "--cflags", "--libs", "gtk+-3.0", "json-glib-1.0"], text=True))
    with tempfile.TemporaryDirectory(prefix="routervpn-gtk-device-") as tmp:
        directory = Path(tmp)
        (directory / FIXTURE.name).write_text(FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")
        for name, replacement in [("shipping", None), *variants.items()]:
            body = source
            if replacement is not None:
                old, new = replacement
                if body.count(old) != 1:
                    raise AssertionError(f"Mutation drifted: {name}")
                body = body.replace(old, new, 1)
            (directory / INCLUDE.name).write_text(body, encoding="utf-8")
            binary = directory / name
            run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", directory / FIXTURE.name, "-o", binary, *flags])
            run(["xvfb-run", "-a", binary], broken=replacement is not None)
            if replacement is not None:
                print("PASS: rejected broken " + name, flush=True)
    print("GTK shipping device settings, captured owner, atomic policy/startup Save and negative controls: PASS", flush=True)


if __name__ == "__main__":
    main()
