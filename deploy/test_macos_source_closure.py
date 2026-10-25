#!/usr/bin/env python3
"""Keep native AppKit source extensions in the shipping swiftc invocation."""
from pathlib import Path
import argparse
import re
import shlex
import unittest

ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "client/macos/build-native-app.sh"
EXTERNAL = ROOT / "client/macos/RouterVPNMacExternalNode.swift"


def compiler_invocation(text):
    lines = text.splitlines()
    starts = [index for index, line in enumerate(lines) if line.startswith("xcrun swiftc ")]
    if len(starts) != 1:
        raise ValueError("Expected exactly one shipping AppKit compiler invocation")
    start = end = starts[0]
    while lines[end].endswith("\\"):
        end += 1
        if end >= len(lines):
            raise ValueError("Unterminated AppKit compiler invocation")
    return "\n".join(lines[start:end+1])


def compiled_inputs(text):
    tokens = shlex.split(compiler_invocation(text).replace("\\\n", " "))
    variables = dict(re.findall(r'^([A-Z_]+)="([^"\n]+)"$', text, re.MULTILINE))
    paths = []
    for token in tokens:
        if re.fullmatch(r"\$[A-Z_]+", token):
            value = variables.get(token[1:], "")
            if value.startswith("$ROOT/") and value.endswith(".swift"):
                paths.append(ROOT / value[len("$ROOT/"):])
    if len(paths) != len(set(paths)):
        raise ValueError("A shipping Swift extension appears more than once")
    return set(paths)


def verify(text):
    paths = compiled_inputs(text)
    required = {
        EXTERNAL,
        ROOT / "client/macos/RouterVPNMacSpeedLab.swift",
        ROOT / "client/macos/RouterVPNMacSpeedLabTransport.swift",
        ROOT / "client/macos/RouterVPNMacViaEntryCandidates.swift",
        ROOT / "client/macos/RouterVPNMacViaEntryPolicy.swift",
        ROOT / "client/macos/RouterVPNMacDeviceSettings.swift",
    }
    if not required <= paths or any(not path.is_file() for path in paths):
        raise ValueError("A native external/path/measurement extension is absent from the actual compiler inputs")
    source = EXTERNAL.read_text()
    for method in ("func showExternalPath(", "func populateIdentityPopup(", "func addExternalNode("):
        if method not in source:
            raise ValueError("The compiled external-node extension lost a shipping callback")
    unified = (ROOT / "client/macos/RouterVPNMacUnifiedShell.swift").read_text()
    if '#selector(addExternalNode)' not in unified:
        raise ValueError("The external-node maker has no shipping native entry point")


class NativeSourceClosure(unittest.TestCase):
    def test_shipping_compiler_inputs(self):
        verify(BUILDER.read_text())

    def test_a_declared_but_uncompiled_extension_is_rejected(self):
        source = BUILDER.read_text()
        invocation = compiler_invocation(source)
        for variable, filename in (("EXTERNAL_NODE_SRC", "RouterVPNMacExternalNode.swift"),
                                   ("DEVICE_SETTINGS_SRC", "RouterVPNMacDeviceSettings.swift")):
            with self.subTest(extension=filename):
                token = '"$'+variable+'"'
                self.assertIn(token, invocation)
                changed = source.replace(invocation, invocation.replace(token, ''), 1)
                self.assertIn(variable+'="$ROOT/client/macos/'+filename+'"', changed)
                with self.assertRaisesRegex(ValueError, "absent"):
                    verify(changed)

    def test_duplicated_extension_is_rejected(self):
        source = BUILDER.read_text()
        invocation = compiler_invocation(source)
        changed = source.replace(invocation, invocation.replace('"$EXTERNAL_NODE_SRC"', '"$EXTERNAL_NODE_SRC" "$EXTERNAL_NODE_SRC"'), 1)
        with self.assertRaisesRegex(ValueError, "more than once"):
            verify(changed)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shipping-only", action="store_true")
    args = parser.parse_args()
    if args.shipping_only:
        verify(BUILDER.read_text())
        print("macOS actual compiler source closure: PASS")
    else:
        unittest.main(argv=[__file__])
