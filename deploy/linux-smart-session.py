"""Log in on the selected real VT and retain the installed controller's owner pipe."""
import json
import os
import pty
import pwd
import re
import select
import signal
import subprocess
import sys
import termios
import time
from pathlib import Path


def answer_password(terminal, password, deadline):
    # polkit 124 flushes input while disabling echo *after* printing its prompt.
    # Wait for that change before writing the private administrator password.
    while termios.tcgetattr(terminal)[3] & termios.ECHO:
        if time.monotonic() >= deadline:
            raise RuntimeError("The stock PolicyKit password prompt did not disable terminal echo")
        time.sleep(.01)
    os.write(terminal, password + b"\n")


def main(directory):
    name = pwd.getpwuid(os.getuid()).pw_name
    tty = os.path.basename(os.ttyname(0))
    active = Path("/sys/class/tty/tty0/active").read_text().strip()
    session = os.environ["XDG_SESSION_ID"]
    fields = dict(line.split("=", 1) for line in subprocess.check_output(
        ["loginctl", "show-session", session], text=True).splitlines() if "=" in line)
    if tty != active or fields.get("VTNr") != tty.removeprefix("tty") or any(
        fields.get(key) != value for key, value in
        {"Name": name, "Seat": "seat0", "Remote": "no", "Active": "yes"}.items()
    ):
        raise RuntimeError("The qualification user has no active local foreground loginctl seat")
    # The stock policy prompts the active session's administrator. Register its
    # text agent on a private PTY, keeping the password out of the VT and logs.
    read_fd, notify = os.pipe()
    agent, terminal = pty.fork()
    if agent == 0:
        os.close(read_fd)
        os.set_inheritable(notify, True)
        os.environ["LC_ALL"] = "C"
        os.execl("/usr/bin/pkttyagent", "pkttyagent", "--process", str(os.getppid()),
                 "--notify-fd", str(notify))
    os.close(notify)
    controller = None
    writer = None
    try:
        if not select.select([read_fd], [], [], 15)[0] or os.read(read_fd, 1):
            raise RuntimeError("PolicyKit text agent failed to register")
        read_pipe, writer = os.pipe()
        os.fchmod(writer, 0o600)
        frame = json.loads((directory / "frame").read_bytes())
        os.write(writer, json.dumps(frame).encode() + b"\n")
        controller = subprocess.Popen(
            ["/usr/bin/pkexec", "--disable-internal-agent", "/opt/router-vpn-client/router-vpn-client",
             "--linux-owned-controller"], stdin=read_pipe, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.close(read_pipe)
        password = (directory / "password").read_bytes().strip()
        deadline = time.monotonic() + 60
        answered = False
        correct_action = False
        prompt = b""
        while not answered:
            if controller.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("The installed controller did not receive the stock auth_admin challenge")
            if not select.select([terminal], [], [], 0.2)[0]:
                continue
            prompt += os.read(terminal, 4096)
            correct_action |= b"==== AUTHENTICATING FOR com.eabusham.routervpn.controller ====" in prompt
            if b"Choose identity" in prompt and b":" in prompt.rsplit(b"Choose identity", 1)[1]:
                match = re.search(rb"(?m)^\s*(\d+)\.\s+[^\r\n]*\b" + re.escape(name.encode()) + rb"\b", prompt)
                if not match:
                    raise RuntimeError("PolicyKit did not offer the disposable administrator")
                os.write(terminal, match[1] + b"\n")
                prompt = b""
            if re.search(rb"(?i)password:\s*$", prompt):
                if not correct_action:
                    raise RuntimeError("PolicyKit requested an unexpected authorization action")
                answer_password(terminal, password, deadline)
                answered = True
        (directory / "pid").write_text(str(controller.pid))
        while not (directory / "close").exists():
            if controller.poll() is not None:
                raise RuntimeError("The installed controller exited before release of its original owner")
            time.sleep(0.1)
    finally:
        if writer is not None:
            os.close(writer)
        try:
            if controller is not None:
                controller.wait(timeout=120)
        finally:
            try:
                os.kill(agent, signal.SIGTERM)
            except ProcessLookupError:
                pass
            os.waitpid(agent, 0)
            os.close(read_fd)
            os.close(terminal)


if __name__ == "__main__":
    directory = Path(sys.argv[1])
    try:
        main(directory)
    except Exception as exc:
        (directory / "failure").write_text(str(exc))
        raise SystemExit(1)
