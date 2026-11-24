"""Fetch one complete Git commit for a pinned mobile dependency."""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

DEPENDENCIES = {
    "https://github.com/SagerNet/sing-box.git",
    "https://github.com/XTLS/libXray.git",
    "https://github.com/XTLS/Xray-core.git",
}


def github_checkout_header():
    """Reuse the current Actions checkout's credential for a single GitHub fetch."""
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("GITHUB_SERVER_URL") != "https://github.com":
        return None
    workspace = os.environ.get("GITHUB_WORKSPACE")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if not workspace or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        return None

    def setting(name):
        result = subprocess.run(["git", "-C", workspace, "config", "--local", "--get", name],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        return result.stdout.rstrip("\n") if result.returncode == 0 else ""

    if setting("remote.origin.url").removesuffix(".git") != f"https://github.com/{repository}":
        return None
    header = setting("http.https://github.com/.extraheader")
    return header if re.fullmatch(r"Authorization: basic [A-Za-z0-9+/=]+", header, re.IGNORECASE) else None


def fetch(url, commit, destination):
    if url not in DEPENDENCIES or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Expected an official mobile dependency URL and full commit ID.")
    if destination.exists() or destination.is_symlink():
        raise ValueError("The generated dependency destination must be empty.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    header = github_checkout_header()
    fetch_env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    options = ["-c", "http.followRedirects=false"]
    if header:
        # The checkout retains its credential. The new repository gets the
        # public remote URL and this exact fetch receives a path-scoped header.
        fetch_env["ROUTERVPN_PIN_FETCH_HEADER"] = header
        fetch_env["GIT_TRACE_REDACT"] = "1"
        options.append(f"--config-env=http.{url}.extraHeader=ROUTERVPN_PIN_FETCH_HEADER")
    for attempt in range(1, 4):
        print(f"Fetching {url} at {commit} (attempt {attempt}/3)...", flush=True)
        with tempfile.TemporaryDirectory(prefix="mobile-pinned-source-", dir=destination.parent) as stage:
            worktree = Path(stage) / "checkout"
            subprocess.run(["git", "init", "--quiet", str(worktree)], check=True)
            git = ["git", "-C", str(worktree)]
            subprocess.run(git + ["remote", "add", "origin", url], check=True)
            result = subprocess.run(git + options + ["fetch", "--no-tags", "--depth=1", "origin", commit], env=fetch_env)
            if result.returncode == 0:
                result = subprocess.run(git + ["checkout", "--quiet", "--detach", "FETCH_HEAD"])
            if result.returncode == 0:
                actual = subprocess.check_output(git + ["rev-parse", "HEAD"], text=True).strip()
                if actual != commit:
                    raise ValueError("Fetched dependency differs from its required Git commit.")
                worktree.rename(destination)
                return
        if attempt < 3:
            time.sleep(attempt * 3)
    raise RuntimeError(f"Could not fetch the pinned dependency after three attempts: {url}")


if __name__ == "__main__":
    fetch(sys.argv[1], sys.argv[2], Path(sys.argv[3]))
