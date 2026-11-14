"""Capture the test-only Darwin race compiler without changing package pins.

Go 1.26.5 contains golang/go#79806's Darwin fork/pre-exec race fix.
The native production builder remains pinned independently.
"""
from pathlib import Path
import json
import os
import platform
import subprocess

TOOLCHAIN = 'go1.26.5'


def readback(compiler, source, environment):
    result = subprocess.run([str(compiler), 'env', '-json', 'GOROOT', 'GOVERSION',
                             'GOHOSTOS', 'GOHOSTARCH', 'GOOS', 'GOARCH'],
                            cwd=source, env=environment, check=True, timeout=180,
                            capture_output=True, text=True)
    return json.loads(result.stdout)


def capture(source, go, environment):
    arch = {'x86_64': 'amd64', 'arm64': 'arm64'}.get(platform.machine())
    if platform.system() != 'Darwin' or arch is None:
        raise ValueError('Darwin race validation requires its actual native compiler host')
    selected = dict(environment, GOTOOLCHAIN=TOOLCHAIN)
    # A captured production GOROOT belongs to 1.26.3. Let the selected official
    # toolchain resolve its own root before disabling further dispatch.
    selected.pop('GOROOT', None)
    identity = readback(go, source, selected)
    if not isinstance(identity, dict) or any(identity.get(key) != value for key, value in
            {'GOVERSION': TOOLCHAIN, 'GOHOSTOS': 'darwin', 'GOHOSTARCH': arch,
             'GOOS': 'darwin', 'GOARCH': arch}.items()):
        raise ValueError('Darwin race validation did not select the exact native Go 1.26.5 compiler')
    root = Path(identity.get('GOROOT', ''))
    compiler = root/'bin/go'
    if not root.is_absolute() or not compiler.is_file() or not os.access(compiler, os.X_OK):
        raise ValueError('Darwin race compiler is not an available absolute executable')
    captured = dict(selected, GOROOT=str(root), GOTOOLCHAIN='local',
                    PATH=str(compiler.parent)+os.pathsep+selected.get('PATH', os.defpath))
    if readback(compiler, source, captured) != identity:
        raise ValueError('Darwin race compiler changed before compilation')
    return compiler, captured


def command(command, source, environment):
    """Select only native Go race builds; preserve production and other hosts."""
    if (platform.system() == 'Darwin' and len(command) > 1
            and Path(command[0]).name == 'go' and command[1] in ('test', 'build') and '-race' in command):
        compiler, environment = capture(source, command[0], environment)
        command = [compiler, *command[1:]]
    return command, environment


def verify_image(compiler, image, source, environment):
    """Bind the receipt version to the exact generated executable."""
    result = subprocess.run([str(compiler), 'version', str(image)], cwd=source,
                            env=environment, check=True, timeout=30,
                            capture_output=True, text=True)
    if result.stdout.strip() != str(image)+': '+TOOLCHAIN:
        raise ValueError('Darwin race image does not carry its captured validation compiler')
