#!/usr/bin/env python3
"""Refuse incomplete/foreign generated native receipts; no native acceptance is simulated."""
from pathlib import Path
import copy
import hashlib
import importlib.util
import json
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("trusted_darwin_socks_child", ROOT/"deploy/validate-darwin-socks-child.py")
V = importlib.util.module_from_spec(spec); sys.modules[spec.name] = V; spec.loader.exec_module(V)

def transcript(harness, native, cases):
    rows = ["=== RUN   "+harness, "=== RUN   "+native]
    for name in cases:
        rows.extend(("=== RUN   "+native+"/"+name, "    native.go:1: verified original Darwin child retirement: "+name))
    rows.append("--- PASS: "+native+" (1.00s)")
    rows.extend("    --- PASS: "+native+"/"+name+" (0.10s)" for name in cases)
    rows.extend(("PASS", "--- PASS: "+harness+" (2.00s)", "PASS"))
    return "\n".join(rows)+"\n"

def envelope(arch):
    metadata = {"source_sha":"a"*40, "source_tree":"b"*40}
    outputs = [transcript(V.BASE.HARNESS, V.BASE.NATIVE, V.ORIGINAL),
               transcript(V.HARNESS, V.NATIVE, V.TYPED)]
    sources = {name:"c"*64 for name in V.REQUIRED_SOURCES}
    def hashed(value):
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    child = {"bytes":1000, "sha256":"d"*64}; peer = {"bytes":2000, "sha256":"e"*64}
    ordinary = {"schema":1, "gate":"generated-darwin-ordered-child", "scope":"generated-command-utun",
                "target":"darwin/"+arch, "toolchain":V.BASE.BUILD.TOOLCHAIN, "cases":list(V.ORIGINAL),
                "pins":{"sing-box":V.BASE.BUILD.PIN, "xray":V.BASE.BUILD.POLICY.XRAY.XRAY_PIN},
                "source_files":sources, "source_sha256":hashed(sources),
                "artifacts":{"generated-child-test":child,"independent-ordered-peer":peer},
                "output_sha256":V.digest(outputs[0].encode())}
    typed_sources = dict(sources, **{"gate/test_darwin_socks_child_tun.py":"f"*64,
                                  "gate/test_darwin_socks_child_tun_runner.py":"1"*64})
    value = {"schema":1,"gate":"generated-darwin-ordered-socks-child","scope":"actual-generated-command-pf-utun",
             "target":"darwin/"+arch,"toolchain":V.BASE.BUILD.TOOLCHAIN,"cases":list(V.TYPED),
             "public_darwin_admission":"closed","repository":{"repository":"Eabusham2/router-vpn", "commit":metadata["source_sha"], "tree":metadata["source_tree"]},
             "source_files":typed_sources,"source_sha256":hashed(typed_sources),
             "artifacts":{"generated-child-test":copy.deepcopy(child),"independent-encrypted-peer":copy.deepcopy(peer)},
             "output_sha256":V.digest(outputs[1].encode()),"original_eight":ordinary}
    return value, metadata, outputs

def require_workflow(raw):
    if not isinstance(raw, str) or len(raw) > 100000 or raw.count("          - darwin-socks-child\n") != 1:
        raise ValueError("Fixed native suite is absent or repeated")
    if "  validate:\n    if: inputs.suite != 'darwin-socks-child' && inputs.suite != 'darwin-socks-installed'\n" not in raw:
        raise ValueError("Generated native suite acquired an extra generic runner")
    marker = "\n  darwin-socks-child:\n"
    if raw.count(marker) != 1:
        raise ValueError("Native architecture job is absent or repeated")
    body = raw.split(marker)[1]
    required = (
        "    if: inputs.suite == 'darwin-socks-child'\n",
        "    timeout-minutes: 75\n",
        "      fail-fast: false\n",
        "          - arch: amd64\n            runner: macos-15-intel\n",
        "          - arch: arm64\n            runner: macos-15\n",
        "      GOOS: darwin\n", "      GOARCH: ${{ matrix.arch }}\n",
        "          ref: ${{ github.sha }}\n", "          ref: ${{ inputs.source_sha }}\n",
        "          go-version: '1.26.3'\n",
        "          python3 candidate/deploy/test_darwin_node_child_tun_runner.py\n",
        "          python3 candidate/deploy/test_darwin_socks_child_tun_runner.py\n",
        "          python3 candidate/deploy/test_desktop_socks_child_sources.py\n",
        '        run: python3 validator/deploy/validate-darwin-socks-child.py --source candidate --source-sha "$SOURCE_SHA" --output validation-output/tests --go "$(command -v go)"\n',
        '                   "state":"scheduled", "native_accepted":False,\n',
    )
    if any(body.count(value) != 1 for value in required):
        raise ValueError("Native job changed fixed source, architecture or execution")
    if body.count("          persist-credentials: false\n") != 2 or body.count("      - uses: actions/upload-artifact@v4\n") != 2 or body.count("        if: ${{ !cancelled() }}\n") != 2:
        raise ValueError("Native evidence or checkout ownership changed")
    checkpoint = body.index("      - name: Preserve scheduled source checkpoint")
    upload = body.index("      - uses: actions/upload-artifact@v4")
    native = body.index("      - name: Require original eight and typed eight")
    if not checkpoint < upload < native or "continue-on-error" in body or "|| true" in body:
        raise ValueError("Native step omitted its completed checkpoint or refusal")
    if body.count("            runner: ") != 2:
        raise ValueError("Native job changed its architecture inventory")

class FixedNativeWorkflow(unittest.TestCase):
    def test_exact_source_allowlist_contains_only_the_generated_union(self):
        paths = V.IDENTITY.ALLOWLISTS["darwin-socks-child"]
        self.assertEqual(len(paths),58)
        self.assertIn("mobile/desktop/node_chain_command_runtime_test.go.tmpl",paths)
        self.assertIn("modes/kill-switch-platform.py",paths)
        self.assertIn('internal/mobilemultihop/node_chain_socks_source.go',paths)
        self.assertIn('internal/mobilemultihop/desktop_node_chain_socks_policy.go',paths)
        self.assertIn('internal/mobilemultihop/node_chain_socks_integrity.go',paths)
        self.assertIn('internal/mobilemultihop/node_chain_socks_integrity_test.go',paths)
        self.assertIn("mobile/desktop/node_chain_imported_test.go.tmpl",paths)
        self.assertFalse(any(path.startswith("cmd/client/") for path in paths))
        self.assertFalse(any(path.startswith(".github/") or path=="deploy/focused_source_identity.py" for path in paths))

    def test_two_native_architectures_have_a_completed_scheduled_checkpoint(self):
        raw = (ROOT/".github/workflows/focused-source-validation.yml").read_text()
        require_workflow(raw)

    def test_missing_architecture_source_control_or_checkpoint_is_refused(self):
        raw = (ROOT/".github/workflows/focused-source-validation.yml").read_text()
        faults = (
            ("            runner: macos-15-intel", "            runner: ubuntu-24.04"),
            ("          - arch: arm64", "          - arch: amd64"),
            ("    timeout-minutes: 75", "    timeout-minutes: 999"),
            ("          go-version: '1.26.3'", "          go-version: '1.25.0'"),
            ("          ref: ${{ inputs.source_sha }}", "          ref: main"),
            ("candidate/deploy/test_darwin_node_child_tun_runner.py", "candidate/deploy/foreign.py"),
            ('"state":"scheduled", "native_accepted":False', '"state":"passed", "native_accepted":True'),
            ("      - name: Require original eight and typed eight", "      - name: Require optional native"),
        )
        prefix, body = raw.split("\n  darwin-socks-child:\n")
        for original, changed in faults:
            self.assertEqual(body.count(original),1)
            with self.subTest(original=original), self.assertRaises((ValueError,IndexError)):
                require_workflow(prefix+"\n  darwin-socks-child:\n"+body.replace(original,changed))

class GeneratedNativeReceipt(unittest.TestCase):
    def test_both_matching_architectures_require_original_and_typed_eight(self):
        for arch in ("amd64", "arm64"):
            value, metadata, outputs = envelope(arch)
            V.require_native(value, arch, metadata, outputs)

    def test_every_native_case_and_exact_original_join_is_required(self):
        for kind in ("original", "typed"):
            value, metadata, outputs = envelope("arm64")
            names = V.ORIGINAL if kind == "original" else V.TYPED
            index = 0 if kind == "original" else 1
            for name in names:
                for fault in ("missing-run", "missing-join", "duplicate", "failed", "skipped", "race"):
                    raw = outputs[index]
                    if fault == "missing-run":
                        native = V.BASE.NATIVE if index == 0 else V.NATIVE
                        raw = raw.replace("=== RUN   "+native+"/"+name+"\n", "", 1)
                    elif fault == "missing-join": raw = raw.replace("verified original Darwin child retirement: "+name, "unproved")
                    elif fault == "duplicate": raw += "    native.go:1: verified original Darwin child retirement: "+name+"\n"
                    elif fault == "failed": raw += "--- FAIL: "+name+" (0.10s)\n"
                    elif fault == "skipped": raw += "--- SKIP: "+name+" (0.10s)\n"
                    else: raw += "WARNING: DATA RACE\n"
                    changed = list(outputs); changed[index] = raw
                    broken = copy.deepcopy(value)
                    (broken["original_eight"] if index == 0 else broken)["output_sha256"] = V.digest(raw.encode())
                    with self.subTest(kind=kind, name=name, fault=fault), self.assertRaises(ValueError):
                        V.require_native(broken, "arm64", metadata, changed)

    def test_foreign_source_architecture_or_acceptance_scope_is_refused(self):
        for fault in ("repository","target","scope","admission","native-claim","toolchain","schema-bool","cases","original-cases","pins","original-native-claim"):
            value, metadata, outputs = envelope("amd64")
            if fault == "repository": value["repository"]["commit"] = "0"*40
            elif fault == "target": value["target"] = "darwin/arm64"
            elif fault == "scope": value["scope"] = "native-compilation-only"
            elif fault == "admission": value["public_darwin_admission"] = "open"
            elif fault == "native-claim": value["native_accepted"] = True
            elif fault == "toolchain": value["toolchain"] = "foreign"
            elif fault == "schema-bool": value["schema"] = True
            elif fault == "cases": value["cases"] = value["cases"][:-1]
            elif fault == "original-cases": value["original_eight"]["cases"] = value["cases"]
            elif fault == "pins": value["original_eight"]["pins"]["sing-box"] = "0"*40
            else: value["original_eight"]["native_accepted"] = False
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                V.require_native(value, "amd64", metadata, outputs)

    def test_every_original_source_and_image_must_match_both_invocations(self):
        for fault in ("source-hash","source-byte","missing-owner","missing-extra","child-image","peer-image","empty-image","bool-size","missing-invocation","extra-invocation","output-hash"):
            value, metadata, outputs = envelope("arm64")
            if fault == "source-hash": value["source_sha256"] = "0"*64
            elif fault in ("source-byte","missing-owner","missing-extra"):
                key = next(iter(V.REQUIRED_SOURCES)) if fault != "missing-extra" else "gate/test_darwin_socks_child_tun.py"
                if fault == "source-byte": value["source_files"][key] = "0"*64
                else: del value["source_files"][key]
                value["source_sha256"] = V.digest(json.dumps(value["source_files"],sort_keys=True,separators=(",",":")).encode())
            elif fault == "child-image": value["artifacts"]["generated-child-test"]["sha256"] = "0"*64
            elif fault == "peer-image": value["artifacts"]["independent-encrypted-peer"]["sha256"] = "0"*64
            elif fault == "empty-image": value["artifacts"]["generated-child-test"]["bytes"] = 0
            elif fault == "bool-size": value["artifacts"]["generated-child-test"]["bytes"] = True
            elif fault == "missing-invocation": outputs.pop()
            elif fault == "extra-invocation": outputs.append(outputs[-1])
            else: value["output_sha256"] = "0"*64
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                V.require_native(value, "arm64", metadata, outputs)

    def test_composed_driver_preserves_both_original_logs_and_refuses_failure_or_drift(self):
        for fault in (None, "native-failure", "source-drift", "foreign-receipt"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); source = root/"candidate"; source.mkdir()
                original = source/"original.go"; original.write_text("original")
                output = root/"validation"/"tests"; output.parent.mkdir()
                result, metadata, outputs = envelope("arm64")
                state = {"index":0}
                def capture(command, **kwargs):
                    index = state["index"]; state["index"] += 1
                    if fault == "native-failure" and index == 1:
                        raise RuntimeError("original native group could not be joined")
                    return outputs[index]
                base = types.SimpleNamespace(CASES=V.ORIGINAL, native_output=capture)
                def standalone(go, *, environment, required_commit, receipt):
                    self.assertEqual(go, "/captured/go")
                    self.assertEqual(required_commit, metadata["source_sha"])
                    self.assertEqual(environment["ROUTERVPN_DARWIN_NODE_CHILD_ACCEPTANCE"], "1")
                    self.assertEqual(environment["ROUTERVPN_DARWIN_SOCKS_CHILD_ACCEPTANCE"], "1")
                    self.assertEqual(environment["CGO_ENABLED"], "1")
                    for name in ("ordinary", "typed"): base.native_output([name], timeout=960)
                    if fault == "source-drift": original.write_text("changed")
                    if fault == "foreign-receipt": result["target"] = "darwin/amd64"
                    receipt.write_text(json.dumps(result))
                    return result
                gate = types.SimpleNamespace(BASE=base, CASES=V.TYPED, HARNESS=V.HARNESS, NATIVE=V.NATIVE, standalone=standalone)
                def snapshot(_): return {"original.go":V.digest(original.read_bytes())}
                with patch.object(V.platform,"system",return_value="Darwin"), patch.object(V.platform,"machine",return_value="arm64"), \
                     patch.object(V,"selection",return_value=(metadata,b"original selection")), patch.object(V.CORE,"snapshot",side_effect=snapshot), \
                     patch.object(V,"module",return_value=gate), patch.object(V.shutil,"which",return_value="/captured/go"):
                    if fault:
                        with self.assertRaises((RuntimeError,ValueError)):
                            V.validate(source, metadata["source_sha"], output)
                    else:
                        self.assertTrue(V.validate(source, metadata["source_sha"], output)["accepted"])
                observed = json.loads((output/"manifest.json").read_text())
                self.assertIs(observed["accepted"], fault is None)
                self.assertFalse(observed["installed_controller_accepted"])
                self.assertEqual((output/"native-original.log").read_text(), outputs[0])
                self.assertIs(base.native_output,capture)
                if fault == "native-failure":
                    self.assertIn("could not be joined",(output/"native-socks-failure.log").read_text())
                else:
                    self.assertEqual((output/"native-socks.log").read_text(), outputs[1])

    def test_non_darwin_refuses_before_any_source_or_native_work(self):
        with patch.object(V.platform, "system", return_value="Linux"), patch.object(V,"selection") as selected:
            with self.assertRaisesRegex(ValueError,"matching Darwin"):
                V.validate(Path("/missing"), "a"*40, Path("/missing-output"))
            selected.assert_not_called()

if __name__ == "__main__":
    unittest.main(verbosity=2)
