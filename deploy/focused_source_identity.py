#!/usr/bin/env python3
"""Bind a read-only hosted validation to its trusted base and exact candidate.

The validator checkout is the parent of this helper's deploy directory. A
candidate may equal that captured base or be exactly one single-parent commit
above it. No ref is updated and no candidate code is executed by this helper.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
import unittest

REPOSITORY = "Eabusham2/router-vpn"
WORKFLOW_REF = "refs/heads/main"
HEX40 = re.compile(r"[0-9a-f]{40}")
ALLOWLISTS = {
    "ordered-clock": frozenset({
        "internal/mobilemultihop/node_chain_execution_proof.go",
        "internal/mobilemultihop/node_chain_execution_runtime.go",
        "internal/mobilemultihop/node_chain_execution_proof_clock_test.go",
    }),
    "legacy-clock": frozenset({
        "internal/mobilemultihop/runtime.go",
        "internal/mobilemultihop/plan.go",
        "internal/mobilemultihop/runtime_proof_clock_test.go",
    }),
    "android-tor": frozenset({"android/test_android_tor_profile.py"}),
    "android-prefix-owner": frozenset({"android/test_android_node_candidate_preparation_owner.py"}),
    "macos-profiles": frozenset({
        "client/macos/RouterVPNConnectionProfiles.swift",
        "deploy/test_desktop_connection_profile_modes.py",
    }),
    "socks-source": frozenset({
        "internal/mobilemultihop/node_chain_imported_socks.go",
        "internal/mobilemultihop/node_chain_socks_source.go",
        "internal/mobilemultihop/node_chain_socks_source_test.go",
    }),
    "linux-hy2": frozenset({
        "mobile/desktop/node_chain_peer_linux_test.go.tmpl",
        "mobile/desktop/node_chain_hysteria_final_test.go.tmpl",
        "cmd/client/desktop_node_chain_linux_tun_native_test.go",
        "cmd/client/desktop_node_chain_linux_hysteria_tun_native_test.go",
        "deploy/test_linux_node_host_tun.py",
        "deploy/test_linux_node_host_tun_runner.py",
        "deploy/test_macos_node_chain_host_runner.py",
    }),
}
REGULAR_MODES = {"100644", "100755"}


def git(root, *arguments):
    command = ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
               "-c", "core.untrackedCache=false", "-c", "core.fileMode=true", "-C", str(root), *arguments]
    environment = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    result = subprocess.run(command, check=False, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=30, env=environment)
    if result.returncode:
        raise ValueError("source identity Git read failed: " + arguments[0])
    return result.stdout


def exact_sha(value, label):
    if not isinstance(value, str) or HEX40.fullmatch(value) is None:
        raise ValueError(label + " must be exactly forty lowercase hexadecimal characters")
    return value


def original_checkout(path, expected):
    path = Path(path)
    if path.is_symlink() or not path.is_dir():
        raise ValueError("source identity requires an original checkout directory")
    root = path.resolve(strict=True)
    top = git(root, "rev-parse", "--show-toplevel").decode("utf-8").strip()
    if Path(top).resolve(strict=True) != root:
        raise ValueError("source identity requires the complete checkout root")
    if git(root, "rev-parse", "--verify", "HEAD^{commit}").decode().strip() != expected:
        raise ValueError("checkout HEAD differs from its captured exact commit")
    index = git(root, "ls-files", "-v", "-z").split(b"\0")
    if any(entry and not entry.startswith(b"H ") for entry in index):
        raise ValueError("source identity refuses hidden index observation flags")
    # Ignored files also cannot silently become dependencies of the fixture.
    # All compiler outputs and Python bytecode belong outside these checkouts.
    if git(root, "status", "--porcelain=v1", "--untracked-files=all", "--ignored=matching", "--ignore-submodules=none"):
        raise ValueError("source identity refuses a dirty or untracked checkout")
    return root


def commit_parents(root, commit):
    raw = git(root, "cat-file", "-p", commit)
    header = raw.split(b"\n\n", 1)[0]
    return [line[7:].decode("ascii") for line in header.splitlines() if line.startswith(b"parent ")]


def changed_files(root, base, source, suite):
    raw = git(root, "diff-tree", "--no-commit-id", "--no-renames", "--no-ext-diff",
              "--no-textconv", "--raw", "-r", "-z", "--full-index", base, source)
    fields = raw.split(b"\0")
    if fields[-1] != b"" or (len(fields)-1) % 2:
        raise ValueError("source identity received an incomplete raw tree diff")
    changes = []
    for index in range(0, len(fields)-1, 2):
        header = fields[index].decode("ascii").split()
        path = fields[index+1].decode("utf-8")
        if len(header) != 5 or not header[0].startswith(":"):
            raise ValueError("source identity received an ambiguous tree change")
        old_mode, new_mode, old_blob, new_blob, status = header
        old_mode = old_mode[1:]
        if path not in ALLOWLISTS[suite]:
            raise ValueError("candidate changed a path outside its exact suite allowlist")
        if status == "A":
            if old_mode != "000000" or new_mode != "100644" or old_blob != "0"*40:
                raise ValueError("new candidate files must be regular non-executable files")
        elif status == "M":
            if old_mode not in REGULAR_MODES or new_mode != old_mode:
                raise ValueError("candidate changed a file type or existing mode")
        else:
            raise ValueError("candidate deletion, rename, copy or type replacement is forbidden")
        exact_sha(old_blob, "old blob")
        exact_sha(new_blob, "new blob")
        if git(root, "cat-file", "-t", new_blob).strip() != b"blob":
            raise ValueError("candidate source is not an original regular blob")
        actual = root/path
        if actual.is_symlink() or not actual.is_file():
            raise ValueError("candidate worktree substituted a nonregular source")
        observed = hashlib.sha1(b"blob " + str(actual.stat().st_size).encode() + b"\0" +
                                actual.read_bytes()).hexdigest()
        if observed != new_blob:
            raise ValueError("candidate worktree bytes differ from the selected Git blob")
        changes.append(dict(path=path, status=status, old_mode=old_mode, new_mode=new_mode,
                            old_blob=old_blob, new_blob=new_blob))
    if len({change["path"] for change in changes}) != len(changes):
        raise ValueError("candidate repeated a changed source path")
    return sorted(changes, key=lambda change: change["path"])


def capture_identity(*, source, validator, source_sha, base_sha, suite, repository, workflow_ref):
    if repository != REPOSITORY or workflow_ref != WORKFLOW_REF:
        raise ValueError("focused validation is restricted to the original repository main workflow")
    if suite not in ALLOWLISTS:
        raise ValueError("focused validation requires an exact supported suite")
    exact_sha(source_sha, "source SHA")
    exact_sha(base_sha, "captured validator SHA")
    validator = original_checkout(validator, base_sha)
    source = original_checkout(source, source_sha)
    if source == validator or source.is_relative_to(validator) or validator.is_relative_to(source):
        raise ValueError("candidate and trusted validator require separate checkouts")
    if source_sha == base_sha:
        relation, changes = "base", []
    else:
        if commit_parents(source, source_sha) != [base_sha]:
            raise ValueError("candidate must have exactly the captured base as its single parent")
        relation = "single-parent"
        changes = changed_files(source, base_sha, source_sha, suite)
    base_tree = git(validator, "rev-parse", base_sha+"^{tree}").decode().strip()
    source_tree = git(source, "rev-parse", source_sha+"^{tree}").decode().strip()
    exact_sha(base_tree, "validator tree")
    exact_sha(source_tree, "candidate tree")
    if git(source, "rev-parse", base_sha+"^{tree}").decode().strip() != base_tree:
        raise ValueError("candidate parent differs from the original validator tree")
    # Recheck both original worktrees after all commit/blob observations.
    original_checkout(validator, base_sha)
    original_checkout(source, source_sha)
    return dict(schema=1, validation_scope="read-only-source-candidate", suite=suite,
                repository=repository, workflow_ref=workflow_ref,
                validator_sha=base_sha, validator_tree=base_tree,
                base_sha=base_sha, base_tree=base_tree, source_sha=source_sha,
                source_tree=source_tree, relation=relation, changes=changes)


def write_selection(path, metadata, *, source, validator):
    path = Path(path).absolute()
    if path.exists() or path.is_symlink():
        raise ValueError("selection metadata requires a fresh output file")
    for parent in path.parents:
        if parent.is_symlink():
            raise ValueError("selection metadata cannot traverse a linked directory")
    resolved = path.resolve()
    for root in (Path(source).resolve(strict=True), Path(validator).resolve(strict=True)):
        if resolved == root or resolved.is_relative_to(root):
            raise ValueError("selection metadata must remain outside both captured checkouts")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(metadata, output, indent=2, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="focused-source-identity-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.validator, self.source = self.work/"validator", self.work/"candidate"
        self.validator.mkdir()
        self.command(self.validator, "init", "-b", "main")
        self.configure(self.validator)
        for path in ("internal/mobilemultihop/node_chain_execution_proof.go",
                     "internal/mobilemultihop/node_chain_execution_runtime.go",
                     "internal/mobilemultihop/runtime.go", "internal/mobilemultihop/plan.go",
                     "android/test_android_tor_profile.py",
                     "android/test_android_node_candidate_preparation_owner.py", "deploy/trusted-validator.py",
                     ".github/workflows/trusted.yml", ".gitignore"):
            target = self.validator/path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("original source\n" if path != ".gitignore" else "*.ignored\n")
        (self.validator/"internal/mobilemultihop/plan.go").chmod(0o755)
        self.base = self.commit(self.validator, "original trusted source")
        self.command(self.work, "clone", "--no-hardlinks", str(self.validator), str(self.source))
        self.configure(self.source)

    def command(self, root, *args):
        result = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-C", str(root), *args],
                                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        return result.stdout.decode().strip()

    def configure(self, root):
        self.command(root, "config", "user.name", "Identity fixture")
        self.command(root, "config", "user.email", "identity-fixture@example.invalid")
        self.command(root, "config", "core.fileMode", "true")
        self.command(root, "config", "commit.gpgsign", "false")

    def commit(self, root, message):
        self.command(root, "add", "-A")
        self.command(root, "commit", "-m", message)
        return self.command(root, "rev-parse", "HEAD")

    def edit(self, path, body="checked candidate\n"):
        target = self.source/path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)

    def capture(self, suite="ordered-clock", **overrides):
        args = dict(source=self.source, validator=self.validator,
                    source_sha=self.command(self.source, "rev-parse", "HEAD"), base_sha=self.base,
                    suite=suite, repository=REPOSITORY, workflow_ref=WORKFLOW_REF)
        args.update(overrides)
        return capture_identity(**args)

    def test_exact_base_and_deterministic_output(self):
        first = self.capture()
        self.assertEqual(first["relation"], "base")
        self.assertEqual(first["changes"], [])
        self.assertEqual(first, self.capture())
        destination = self.work/"outputs"/"selection.json"
        write_selection(destination, first, source=self.source, validator=self.validator)
        self.assertEqual(json.loads(destination.read_text()), first)
        with self.assertRaisesRegex(ValueError, "fresh"):
            write_selection(destination, first, source=self.source, validator=self.validator)

    def test_each_suite_accepts_only_its_exact_single_parent_files(self):
        for suite, paths in ALLOWLISTS.items():
            with self.subTest(suite=suite):
                self.command(self.source, "reset", "--hard", self.base)
                self.command(self.source, "clean", "-fdx")
                for path in paths: self.edit(path)
                child = self.commit(self.source, "bounded "+suite)
                captured = self.capture(suite)
                self.assertEqual(captured["relation"], "single-parent")
                self.assertEqual(captured["source_sha"], child)
                self.assertEqual({row["path"] for row in captured["changes"]}, paths)
                self.assertEqual(captured["validator_sha"], self.base)

    def test_existing_executable_mode_is_preserved_but_new_executable_is_refused(self):
        self.edit("internal/mobilemultihop/plan.go")
        self.commit(self.source, "preserved original executable mode")
        self.assertEqual(self.capture("legacy-clock")["changes"][0]["new_mode"], "100755")
        self.command(self.source, "reset", "--hard", self.base)
        self.edit("internal/mobilemultihop/runtime_proof_clock_test.go")
        (self.source/"internal/mobilemultihop/runtime_proof_clock_test.go").chmod(0o755)
        self.commit(self.source, "new executable refused")
        with self.assertRaisesRegex(ValueError, "non-executable"): self.capture("legacy-clock")

    def test_deletion_mode_change_and_symlink_are_refused(self):
        path = "internal/mobilemultihop/node_chain_execution_proof.go"
        for mutation in ("delete", "mode", "symlink"):
            with self.subTest(mutation=mutation):
                self.command(self.source, "reset", "--hard", self.base)
                self.command(self.source, "clean", "-fdx")
                target = self.source/path
                if mutation == "delete": target.unlink()
                elif mutation == "mode": target.chmod(0o755)
                else:
                    target.unlink(); target.symlink_to("node_chain_execution_runtime.go")
                self.commit(self.source, mutation)
                with self.assertRaises(ValueError): self.capture()

    def test_foreign_validator_workflow_and_other_suite_changes_are_refused(self):
        for path in ("deploy/trusted-validator.py", ".github/workflows/trusted.yml",
                     "android/test_android_tor_profile.py", "README.md"):
            with self.subTest(path=path):
                self.command(self.source, "reset", "--hard", self.base)
                self.command(self.source, "clean", "-fdx")
                self.edit(path)
                self.commit(self.source, "foreign path")
                with self.assertRaisesRegex(ValueError, "allowlist"): self.capture()

    def test_distant_child_merge_and_wrong_parent_are_refused(self):
        self.edit("internal/mobilemultihop/node_chain_execution_proof.go")
        first = self.commit(self.source, "first")
        self.edit("internal/mobilemultihop/node_chain_execution_runtime.go")
        second = self.commit(self.source, "second")
        with self.assertRaisesRegex(ValueError, "single parent"): self.capture()
        tree = self.command(self.source, "rev-parse", second+"^{tree}")
        merge = self.command(self.source, "commit-tree", tree, "-p", self.base, "-p", first, "-m", "merge refused")
        self.command(self.source, "reset", "--hard", merge)
        with self.assertRaisesRegex(ValueError, "single parent"): self.capture()
        with self.assertRaisesRegex(ValueError, "captured exact commit"):
            self.capture(base_sha=first)

    def test_tracked_untracked_ignored_and_validator_dirt_are_refused(self):
        for where, path in ((self.source, "internal/mobilemultihop/runtime.go"),
                            (self.source, "untracked.py"), (self.source, "hidden.ignored"),
                            (self.validator, "deploy/trusted-validator.py")):
            with self.subTest(where=where.name, path=path):
                for root in (self.source, self.validator):
                    self.command(root, "reset", "--hard", self.base)
                    self.command(root, "clean", "-fdx")
                (where/path).write_text("uncaptured bytes\n")
                with self.assertRaisesRegex(ValueError, "dirty or untracked"): self.capture()

    def test_hidden_index_flags_and_disabled_mode_observation_cannot_hide_dirt(self):
        path = "internal/mobilemultihop/node_chain_execution_proof.go"
        for flag in ("assume-unchanged", "skip-worktree"):
            with self.subTest(flag=flag):
                self.command(self.source, "update-index", "--"+flag, path)
                self.edit(path, "uncaptured masked source\n")
                with self.assertRaisesRegex(ValueError, "index observation flags"): self.capture()
                self.command(self.source, "update-index", "--no-"+flag, path)
                self.command(self.source, "reset", "--hard", self.base)
        self.command(self.source, "config", "core.fileMode", "false")
        (self.source/path).chmod(0o755)
        with self.assertRaisesRegex(ValueError, "dirty or untracked"): self.capture()

    def test_exact_sha_repository_ref_and_suite_are_required(self):
        for override in ({"source_sha": self.base.upper()}, {"source_sha": "main"},
                         {"source_sha": self.base[:-1]}, {"base_sha": "0"*39},
                         {"repository": "another/router-vpn"}, {"workflow_ref": "refs/heads/topic"},
                         {"suite": "all"}):
            with self.subTest(override=override), self.assertRaises(ValueError): self.capture(**override)

    def test_changed_files_cannot_be_reassigned_to_a_different_suite(self):
        self.edit("android/test_android_tor_profile.py")
        self.commit(self.source, "Tor fixture only")
        self.assertEqual(len(self.capture("android-tor")["changes"]), 1)
        for suite in ("ordered-clock", "legacy-clock"):
            with self.subTest(suite=suite), self.assertRaisesRegex(ValueError, "allowlist"): self.capture(suite)

    def test_exact_checkout_roots_and_external_output_are_required(self):
        linked = self.work/"linked-candidate"
        linked.symlink_to(self.source, target_is_directory=True)
        for source in (linked, self.source/"internal", self.validator):
            with self.subTest(source=str(source)), self.assertRaises(ValueError):
                self.capture(source=source)
        metadata = self.capture()
        for output in (self.source/"selection.json", self.validator/"selection.json"):
            with self.subTest(output=str(output)), self.assertRaisesRegex(ValueError, "outside"):
                write_selection(output, metadata, source=self.source, validator=self.validator)
        output_link = self.work/"linked-output"
        output_link.symlink_to(self.work, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "linked"):
            write_selection(output_link/"selection.json", metadata, source=self.source, validator=self.validator)


    def test_actual_cli_binds_its_validator_checkout_and_workflow_sha(self):
        helper = self.validator/"deploy"/"focused_source_identity.py"
        helper.write_bytes(Path(__file__).read_bytes())
        self.base = self.commit(self.validator, "capture the original trusted validator")
        self.command(self.source, "fetch", "origin")
        self.command(self.source, "reset", "--hard", self.base)
        environment = dict(os.environ, GITHUB_REPOSITORY=REPOSITORY, GITHUB_REF=WORKFLOW_REF,
                           GITHUB_SHA=self.base, PYTHONDONTWRITEBYTECODE="1")
        output = self.work/"cli-selection.json"
        arguments = ["python3", str(helper), "--suite", "ordered-clock", "--source", str(self.source),
                     "--source-sha", self.base, "--base-sha", self.base, "--output", str(output)]
        result = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=environment, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(json.loads(output.read_text())["validator_sha"], self.base)
        output.unlink()
        environment["GITHUB_SHA"] = "0"*40
        result = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=environment, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(output.exists())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--suite", choices=tuple(ALLOWLISTS))
    parser.add_argument("--source", type=Path)
    parser.add_argument("--source-sha")
    parser.add_argument("--base-sha")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.self_test:
        if any((args.suite, args.source, args.source_sha, args.base_sha, args.output)):
            parser.error("self-tests cannot select candidate inputs")
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(IdentityTests))
        return 0 if result.wasSuccessful() else 1
    if any(value is None for value in (args.suite, args.source, args.source_sha, args.base_sha, args.output)):
        parser.error("suite, source, source-sha, base-sha and fresh output are required")
    if os.environ.get("GITHUB_SHA") != args.base_sha:
        raise ValueError("captured workflow SHA differs from the original validator base")
    validator = Path(__file__).resolve().parents[1]
    metadata = capture_identity(source=args.source, validator=validator, source_sha=args.source_sha,
                                base_sha=args.base_sha, suite=args.suite,
                                repository=os.environ.get("GITHUB_REPOSITORY"),
                                workflow_ref=os.environ.get("GITHUB_REF"))
    write_selection(args.output, metadata, source=args.source, validator=validator)
    print(json.dumps(metadata, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
