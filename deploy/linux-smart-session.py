"""Log in on the selected real VT and retain the installed controller's owner pipe."""
import json
import os
import pty
import pwd
import re
import select
import signal
import stat
import subprocess
import sys
import termios
import time
from pathlib import Path


def stage(directory, name, **fields):
    # Diagnostics cannot prevent the original owner pipe/agent from joining.
    # Fixed field names and bounded seat/process values only; never prompts,
    # passwords, authorization frames or arbitrary child output.
    try:
        (directory / "stage").write_text(json.dumps({"stage": name, **fields}))
    except Exception:
        pass


def record_failure(directory, error):
    # The first failure survives cleanup, even if diagnostic storage itself fails.
    try:
        try:
            record = json.loads((directory / "stage").read_text())
            if not isinstance(record, dict):
                record = {"stage": "session-start"}
        except (OSError, ValueError):
            record = {"stage": "session-start"}
        record["error_type"] = type(error).__name__
        if isinstance(error, RuntimeError):
            record["reason"] = str(error)[:240]
        if isinstance(error, OSError):
            record["errno"] = error.errno
        if isinstance(error, subprocess.CalledProcessError):
            record["exit_code"] = error.returncode
        descriptor = os.open(directory / "failure", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            json.dump(record, stream)
    except Exception:
        pass


def close_diagnostic(stream):
    try:
        if stream is not None:
            stream.close()
    except Exception:
        pass  # Diagnostic close cannot replace authorization or retirement errors.


def answer_password(terminal, password, deadline):
    # polkit 124 flushes input while disabling echo *after* printing its prompt.
    # Wait for that change before writing the private administrator password.
    while termios.tcgetattr(terminal)[3] & termios.ECHO:
        if time.monotonic() >= deadline:
            raise RuntimeError("The stock PolicyKit password prompt did not disable terminal echo")
        time.sleep(.01)
    os.write(terminal, password + b"\n")


def main(directory):
    stage(directory, "session-user")
    name = pwd.getpwuid(os.getuid()).pw_name
    stage(directory, "foreground-terminal")
    tty = os.path.basename(os.ttyname(0))
    active = Path("/sys/class/tty/tty0/active").read_text().strip()
    stage(directory, "pam-session-environment", tty=tty[:64], active_tty=active[:64])
    session = os.environ.get("XDG_SESSION_ID")
    if not session:
        raise RuntimeError("The stock PAM login did not supply XDG_SESSION_ID")
    stage(directory, "loginctl-session", tty=tty[:64], active_tty=active[:64], session=session[:64])
    fields = dict(line.split("=", 1) for line in subprocess.check_output(
        ["loginctl", "show-session", session], text=True).splitlines() if "=" in line)
    stage(directory, "active-seat-readback", tty=tty[:64], active_tty=active[:64], session=session[:64],
          expected_user=name[:64], expected_uid=os.getuid(),
          seat={key: fields.get(key, "")[:64] for key in ("Name", "User", "VTNr", "Seat", "Remote", "Active")})
    if fields.get("User") != str(os.getuid()) or tty != active or fields.get("VTNr") != tty.removeprefix("tty") or any(
        fields.get(key) != value for key, value in
        {"Name": name, "Seat": "seat0", "Remote": "no", "Active": "yes"}.items()
    ):
        raise RuntimeError("The qualification user has no active local foreground loginctl seat")
    # The stock policy prompts the active session's administrator. Register its
    # text agent on a private PTY, keeping the password out of the VT and logs.
    stage(directory, "policykit-agent-start")
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
    failure = None
    try:
        stage(directory, "policykit-agent-registration")
        if not select.select([read_fd], [], [], 15)[0] or os.read(read_fd, 1):
            raise RuntimeError("PolicyKit text agent failed to register")
        stage(directory, "controller-owner-pipe")
        read_pipe, writer = os.pipe()
        os.fchmod(writer, 0o600)
        frame = json.loads((directory / "frame").read_bytes())
        os.write(writer, json.dumps(frame).encode() + b"\n")
        stage(directory, "controller-pkexec-start")
        # Native startup/retirement diagnostics remain private to this original
        # login. A failed diagnostic open must not alter authorization or cleanup.
        diagnostics = None
        try:
            descriptor = os.open(directory / "controller-stderr",
                                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            diagnostics = os.fdopen(descriptor, "wb", buffering=0)
            os.fchmod(diagnostics.fileno(), 0o600)
            info = os.fstat(diagnostics.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                    stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                close_diagnostic(diagnostics)
                diagnostics = None
        except OSError:
            close_diagnostic(diagnostics)
            diagnostics = None
        try:
            controller = subprocess.Popen(
                ["/usr/bin/pkexec", "--disable-internal-agent", "/opt/router-vpn-client/router-vpn-client",
                 "--linux-owned-controller"], stdin=read_pipe, stdout=subprocess.DEVNULL,
                stderr=diagnostics if diagnostics is not None else subprocess.DEVNULL)
        finally:
            close_diagnostic(diagnostics)
        os.close(read_pipe)
        stage(directory, "policykit-password-input")
        password = (directory / "password").read_bytes().strip()
        deadline = time.monotonic() + 60
        answered = False
        correct_action = False
        prompt = b""
        stage(directory, "policykit-challenge")
        while not answered:
            code = controller.poll()
            if code is not None or time.monotonic() >= deadline:
                stage(directory, "policykit-challenge", controller_exit=code, correct_action=correct_action)
                raise RuntimeError("The installed controller did not receive the stock auth_admin challenge")
            if not select.select([terminal], [], [], 0.2)[0]:
                continue
            prompt += os.read(terminal, 4096)
            correct_action |= b"==== AUTHENTICATING FOR com.eabusham.routervpn.controller ====" in prompt
            if b"Choose identity" in prompt and b":" in prompt.rsplit(b"Choose identity", 1)[1]:
                stage(directory, "policykit-identity-choice", correct_action=correct_action)
                match = re.search(rb"(?m)^\s*(\d+)\.\s+[^\r\n]*\b" + re.escape(name.encode()) + rb"\b", prompt)
                if not match:
                    raise RuntimeError("PolicyKit did not offer the disposable administrator")
                os.write(terminal, match[1] + b"\n")
                prompt = b""
            if re.search(rb"(?i)password:\s*$", prompt):
                stage(directory, "policykit-password-prompt", correct_action=correct_action)
                if not correct_action:
                    raise RuntimeError("PolicyKit requested an unexpected authorization action")
                answer_password(terminal, password, deadline)
                answered = True
        stage(directory, "controller-awaiting-original-proof")
        (directory / "pid").write_text(str(controller.pid))
        while not (directory / "close").exists():
            code = controller.poll()
            if code is not None:
                stage(directory, "controller-owner-lifetime", controller_exit=code)
                raise RuntimeError("The installed controller exited before release of its original owner")
            time.sleep(0.1)
    except BaseException as error:
        failure = error
        record_failure(directory, error)
        raise
    finally:
        try:
            stage(directory, "controller-retirement")
            if writer is not None:
                os.close(writer)
            try:
                if controller is not None:
                    code = controller.wait(timeout=120)
                    stage(directory, "controller-retirement", controller_exit=code)
                    if code != 0 and failure is None:
                        raise RuntimeError("The installed controller exited unsuccessfully during retirement")
            finally:
                try:
                    os.kill(agent, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                os.waitpid(agent, 0)
                os.close(read_fd)
                os.close(terminal)
        except BaseException as error:
            if failure is None:
                raise
            failure.add_note("Session cleanup also failed: " + type(error).__name__)


if __name__ == "__main__":
    directory = Path(sys.argv[1])
    try:
        main(directory)
    except Exception as exc:
        record_failure(directory, exc)
        raise SystemExit(1)
