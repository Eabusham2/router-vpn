#!/usr/bin/env python3
"""Exercise the shipping Windows DNS owner, real loopback HTTP/WPF, and broken guards."""
from __future__ import annotations

import argparse
import contextlib
import http.server
import json
from pathlib import Path
import re
import subprocess
import tempfile
import threading
import time
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "client/RouterVPN-Windows-DNSMeasurement.ps1"
TEST = ROOT / "client/test-windows-dns-measurement.ps1"
PROFILE, TOKEN, SESSION = "external-a", "source-a", "a" * 32
IDS = ("cf4a", "cf4b", "cf6a", "cf6b", "g4a", "g4b", "g6a", "g6b", "q4a", "q4b", "q6a", "q6b")


def run(command, *, rejection: str | None = None, timeout: int = 70):
    result = subprocess.run([str(value) for value in command], text=True, capture_output=True, timeout=timeout)
    if rejection:
        if result.returncode == 0 or rejection not in result.stdout + result.stderr:
            raise AssertionError(f"Negative did not reject its intended broken behavior: {rejection}\n{result.stdout}\n{result.stderr}")
    elif result.returncode:
        raise RuntimeError(f"{command}\n{result.stdout}\n{result.stderr}")
    else:
        print(result.stdout.strip(), flush=True)
    return result


def rows(transport):
    result = [dict(id="selected", name="Saved resolver", kind="selected", address="192.0.2.53", port=8443,
                   transport="https", server_name="home.example", path="/private-query", route="entry",
                   route_label="Selected Home via entry", samples=3, failed=0, ready=True, median_ms=0.01)]
    for index, identifier in enumerate(IDS):
        ready = index < 2
        row = dict(id=identifier, name="Public " + identifier, kind="public", address="1.1.1.1",
                   port={"tcp": 53, "tls": 853, "https": 443}[transport], transport=transport,
                   route="exit", route_label="Captured public exit", samples=3 if ready else 0,
                   failed=0 if ready else 3, ready=ready)
        if transport != "tcp":
            row["server_name"] = "cloudflare-dns.com"
        if transport == "https":
            row["path"] = "/dns-query"
        if ready:
            row["median_ms"] = 7.5 if index == 0 else 2.25
        else:
            row["failure"] = "Unreachable through captured exit"
        result.append(row)
    return result


class State:
    def __init__(self, scenario):
        self.scenario = scenario
        self.lock = threading.Lock()
        self.request = ""
        self.transport = scenario if scenario in ("tcp", "tls") else "https"
        self.started = 0.0
        self.cancelled = 0.0
        self.cancel_count = 0
        self.poll_count = 0
        self.status_count = 0
        self.admitted = 0
        self.replaced = False
        self.selected = False
        self.saved = False
        self.failures = []
        self.bodies = []
        self.last_stage = "idle"
        self.response_history = []
        self.info_pending = threading.Event()
        self.dispatcher_release = threading.Event()
        self.dispatcher_pulses = 0

    def view(self, stage="idle", complete=True, drained=True):
        self.last_stage = stage
        return dict(profile_id=PROFILE, profile_token=TOKEN, session_id=SESSION, request_id=self.request,
                    expires_in_ms=90000 if stage == "complete" else 0,
                    status=dict(schema=1, node_id=PROFILE, session_id=SESSION, request_id=self.request,
                                public_transport=self.transport, stage=stage, complete=complete, drained=drained,
                                results=rows(self.transport) if stage == "complete" else []))

    def check_owner(self, body):
        if body.get("profile_id") != PROFILE or body.get("profile_token") != TOKEN or body.get("session_id") != SESSION:
            self.failures.append("request adopted another node, source or session")
            return False
        request = body.get("request_id", "")
        if not re.fullmatch(r"[0-9a-f]{32}", request):
            self.failures.append("missing fresh bounded request ID")
            return False
        if self.request and self.request != request:
            self.failures.append("operation changed its captured nonce")
            return False
        self.request = request
        return True


@contextlib.contextmanager
def controller(scenario):
    state = State(scenario)

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_):
            pass

        def reply(self, code, value):
            raw = json.dumps(value).encode("utf-8")
            status = value.get("status", {})
            if code == 409:
                state.response_history.append("error")
            elif status.get("complete") is True and status.get("drained") is True and status.get("stage") == "cancelled":
                state.response_history.append("drained")
            try:
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass

        def do_GET(self):
            parsed = urllib.parse.urlsplit(self.path)
            query = urllib.parse.parse_qs(parsed.query)
            if parsed.path == "/fixture/dispatcher-pulse" and not query:
                with state.lock:
                    if not state.info_pending.is_set() or state.dispatcher_release.is_set():
                        return self.reply(409, {"accepted": False})
                    state.dispatcher_pulses += 1
                    if state.dispatcher_pulses == 2:
                        state.dispatcher_release.set()
                    return self.reply(200, {"accepted": True, "pulse": state.dispatcher_pulses})
            if parsed.path == "/api/dns/measurement" and not query:
                # A synchronously blocked UI cannot acknowledge these events.
                # No server lock is held while waiting for dispatcher progress.
                state.info_pending.set()
                if not state.dispatcher_release.wait(5):
                    with state.lock:
                        state.info_pending.clear()
                        state.failures.append("dispatcher blocked behind pending HTTP response")
                    return self.reply(409, {"error": "dispatcher did not make progress"})
            with state.lock:
                if parsed.path == "/api/status" and not query:
                    state.status_count += 1
                    connected = state.status_count == 1
                    return self.reply(200, dict(connected=connected, phase="connected" if connected else "disconnected"))
                if parsed.path != "/api/dns/measurement":
                    state.failures.append("foreign GET route")
                    return self.reply(400, {})
                if not query:
                    if state.request:
                        state.failures.append("recaptured current connection during owned work")
                    return self.reply(200, state.view())
                if query != {"request_id": [state.request]} or not state.request:
                    state.failures.append("poll used a foreign or empty request")
                    return self.reply(409, {})
                state.poll_count += 1
                if scenario == "replacement" and not state.replaced and not state.cancelled:
                    state.replaced = True
                    value = state.view("measuring", False, False)
                    value["profile_token"] = "replacement-source"
                    return self.reply(200, value)
                if scenario == "unavailable" and state.poll_count <= 2:
                    return self.reply(409, {"error": "transient owner query unavailable"})
                if state.cancelled:
                    wait = 0.12 if scenario == "early-close" else 0.7
                    drained = time.monotonic() - state.cancelled >= wait
                    return self.reply(200, state.view("cancelled" if drained else "draining", True, drained))
                complete = bool(state.started) and time.monotonic() - state.started > 0.15
                return self.reply(200, state.view("complete" if complete else "measuring", complete, complete))

        def do_POST(self):
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 4096:
                    raise ValueError("unbounded body")
                body = json.loads(self.rfile.read(size))
            except (ValueError, json.JSONDecodeError):
                return self.reply(400, {})
            with state.lock:
                state.bodies.append((self.path, body))
                if self.path == "/api/dns/policy":
                    expected = dict(profile_id=PROFILE, profile_token=TOKEN, measurement_id=state.request, result_id="cf4b",
                                    mode={"tcp": "custom", "tls": "dot", "https": "doh"}[state.transport],
                                    protocol=state.transport, host="1.1.1.1", port={"tcp": 53, "tls": 853, "https": 443}[state.transport],
                                    server_name="" if state.transport == "tcp" else "cloudflare-dns.com",
                                    path="/dns-query" if state.transport == "https" else "")
                    if state.status_count < 2 or not state.selected or body != expected:
                        state.failures.append("Save omitted exact measured draft or disconnection")
                        return self.reply(409, {})
                    state.saved = True
                    return self.reply(200, dict(expected, profile_token="new-saved-source"))
                if not state.check_owner(body):
                    return self.reply(409, {})
                required = {"profile_id", "profile_token", "session_id", "request_id"}
                if self.path == "/api/dns/measurement/cancel":
                    if set(body) != required:
                        state.failures.append("Cancel copied unrelated fields")
                    if not state.cancelled:
                        state.cancelled = time.monotonic()
                    state.cancel_count += 1
                    if scenario == "unavailable" and state.cancel_count <= 2:
                        return self.reply(409, {"error": "transient cancel unavailable"})
                    drained = time.monotonic() - state.cancelled >= (0.12 if scenario == "early-close" else 0.7)
                    return self.reply(202, state.view("cancelled" if drained else "draining", True, drained))
                if self.path == "/api/dns/measurement/select":
                    if set(body) != required | {"result_id"} or body["result_id"] != "fastest" or state.last_stage != "complete":
                        state.failures.append("Select was not a completed public measurement")
                        return self.reply(409, {})
                    state.selected = True
                    endpoint = rows(state.transport)[2]
                    draft = dict(profile_id=PROFILE, profile_token=TOKEN, measurement_id=state.request, result_id="cf4b",
                                 mode={"tcp": "custom", "tls": "dot", "https": "doh"}[state.transport],
                                 protocol=state.transport, host=endpoint["address"], port=endpoint["port"],
                                 server_name=endpoint.get("server_name", ""), path=endpoint.get("path", ""))
                    return self.reply(200, dict(draft=draft, expires_in_ms=90000, session_id=SESSION, request_id=state.request))
                if self.path != "/api/dns/measurement" or set(body) != required | {"public_transport"} or body["public_transport"] != state.transport:
                    state.failures.append("Start changed captured transport or route")
                    return self.reply(400, {})
            # Delayed admission deliberately permits Cancel to tombstone this
            # nonce before the asynchronous Start reaches native work.
            if scenario == "early-close":
                time.sleep(0.45)
            with state.lock:
                if state.cancelled:
                    return self.reply(409, {"error": "cancelled before admission"})
                state.started = time.monotonic()
                state.admitted += 1
                return self.reply(202, state.view("preparing", False, False))

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", state
    finally:
        state.dispatcher_release.set()
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)


def validate_composition(directory, shell):
    script = directory / "shipping-composition.ps1"
    script.write_text(r'''
param([string]$Root)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2
$Client=Join-Path $Root 'client'
Import-Module (Join-Path $Client 'RouterVPN-Windows-ControllerTransport.psm1') -Global -ErrorAction Stop
$Launcher=Get-Content (Join-Path $Client 'RouterVPN-Windows-App.ps1') -Raw -Encoding UTF8
$LoadStart=$Launcher.IndexOf('$MTUHelpers=');$LoadEnd=$Launcher.IndexOf('# The shipping Windows product',$LoadStart)
$ComposeStart=$Launcher.IndexOf('$Product=Join-Path');$ComposeEnd=$Launcher.IndexOf('$ProductSource=Set-RouterVPNProductHelpBinding -Source $ProductSource',$ComposeStart)
if($LoadStart-lt0-or$LoadEnd-le$LoadStart-or$ComposeStart-lt0-or$ComposeEnd-le$ComposeStart){throw 'Shipping composition boundaries changed'}
. ([ScriptBlock]::Create($Launcher.Substring($LoadStart,$LoadEnd-$LoadStart).Replace('$PSScriptRoot','$Client')))
. ([ScriptBlock]::Create($Launcher.Substring($ComposeStart,$ComposeEnd-$ComposeStart).Replace('$PSScriptRoot','$Client')))
$Ast=[ScriptBlock]::Create($ProductSource).Ast
$Events=@($Ast.FindAll({param($N)$N-is[Management.Automation.Language.InvokeMemberExpressionAst]-and$N.Member.Extent.Text-ceq'Add_Click'-and$N.Expression.Extent.Text-ceq'$DnsButton'},$true))
if($Events.Count-ne1-or$Events[0].Arguments.Count-ne1){throw 'Final composed DNS Retest callback lost or duplicated'}
$Action=[ScriptBlock]::Create($Events[0].Arguments[0].ScriptBlock.EndBlock.Extent.Text)
$script:Posts=0;$script:Panels=0;$script:Busy=$false;$script:Logs=@();$Window='main-window';$BaseUrl='http://127.0.0.1:8788'
function UnifiedAsyncBusy{return $script:Busy}
function Log($Text){$script:Logs+=,$Text}
function StartUnifiedApiAsync {param($Label,$Path,$Method,$Body,$Timeout,$Done,$Failed,$Finally) if($Path-cne'/api/dns/retest'-or$Method-cne'POST'){throw 'Wrong Router retest route'};$script:Posts++;return $true}
function Show-RouterVPNDNSMeasurement {param($BaseUrl,$Owner,$DisplayedProfileID) if($BaseUrl-cne'http://127.0.0.1:8788'-or$Owner-cne'main-window'-or$DisplayedProfileID-cne'external-a'){throw 'Panel lost displayed owner'};$script:Panels++}
function RefreshDnsPolicy{}
function RefreshProduct{}
$RouterCombo=[pscustomobject]@{SelectedValue='external-a';SelectedItem=[pscustomobject]@{id='external-a';node_kind='external'}}
&$Action
if($script:Panels-ne1-or$script:Posts-ne0){throw 'External Retest did not use native measurement panel'}
$RouterCombo.SelectedItem.id='replacement';&$Action
if($script:Panels-ne1-or$script:Posts-ne0){throw 'Retest followed a replacement displayed node'}
$RouterCombo.SelectedItem.id='external-a';$RouterCombo.SelectedItem.node_kind='unknown';&$Action
if($script:Panels-ne1-or$script:Posts-ne0){throw 'Unknown node fell back to Router path'}
$RouterCombo.SelectedItem.node_kind='router-vpn';&$Action
if($script:Posts-ne1-or$script:Panels-ne1){throw 'Router Retest lost asynchronous legacy path'}
$script:Busy=$true;&$Action
if($script:Posts-ne1-or$script:Panels-ne1){throw 'Busy action admitted conflicting Retest'}
Write-Host 'PASS: actual shipping Windows App/helper/Product/Unified DNS Retest composition'
''', encoding="utf-8-sig")
    run([shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script, "-Root", ROOT])


def run_live_case(command, scenario):
    with controller(scenario) as (url, state):
        run(command + ["-Live", "-Scenario", scenario, "-BaseUrl", url])
        if scenario == "early-close":
            time.sleep(0.5)
        if state.failures:
            raise AssertionError(f"{scenario}: {state.failures}")
        if state.dispatcher_pulses != 2:
            raise AssertionError(f"{scenario}: no acknowledged dispatcher progress during held HTTP work")
        if scenario in ("success", "tcp", "tls"):
            if not state.saved or not state.selected or state.admitted != 1 or state.status_count != 2:
                raise AssertionError(f"{scenario}: real measured Save contract was not exercised")
        elif not state.cancelled or not state.cancel_count or state.last_stage != "cancelled":
            raise AssertionError(f"{scenario}: exact native cancellation/drain was not exercised")
        if scenario == "early-close" and state.admitted != 0:
            raise AssertionError("Cancel tombstone did not reject delayed Start admission")
        # Cancel and status are both valid receipt channels. Their scheduling
        # order is not a native cleanup guarantee, especially under WPF. Require
        # the deliberately unavailable reply followed by actual drain proof.
        if scenario == "unavailable":
            history = state.response_history
            if "error" not in history or "drained" not in history or history.index("error") >= len(history) - 1 - history[::-1].index("drained"):
                raise AssertionError("HTTP errors skipped the native drain receipt")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--shell", default="pwsh")
    parser.add_argument("--unit-only", action="store_true")
    args = parser.parse_args()
    command = [args.shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", TEST]
    run(command)
    source = HELPER.read_text(encoding="utf-8")
    with tempfile.TemporaryDirectory(prefix="routervpn-windows-dns-") as temp:
        directory = Path(temp)
        validate_composition(directory, args.shell)
        variants = {
            "source-owner": ("$Token-cne$State.Token", "$false", "CONTROL captured profile_token accepted replacement"),
            "request-owner": ("$Request-cne$State.Request", "$false", "CONTROL foreign request adopted"),
            "drain": ("$State.Drained-or($Complete-and$Drained)", "$State.Drained-or$Complete", "CONTROL complete-but-undrained close accepted"),
            "http-error-drain": ("if($Reply.Code-eq409){$State.Invalid=$true", "if($Reply.Code-eq409){$State.Drained=$true;$State.Invalid=$true", "CONTROL HTTP409 must never be drain proof"),
            "zero-score": ("-and[double]$Median-gt0", "", "CONTROL invalid result zero accepted"),
            "failed-score": ("else{'No valid score'}", "else{'0.00 ms'}", "CONTROL failed candidates fabricated a zero score"),
            "selected-route": ("$State.Selected=$Parsed.Selected", "$State.Selected=''", "CONTROL complete measured catalog not rendered"),
            "draft-owner": ("@('measurement_id',$State.Request)", "@('measurement_id',[string](Get-RouterVPNDNSValue $Draft 'measurement_id' ''))", "CONTROL draft measurement_id accepted changed identity or endpoint"),
            "expiry-clock": ("$RequestedAt.AddMilliseconds([long]$Left)", "[DateTime]::UtcNow.AddMilliseconds([long]$Left)", "CONTROL expiry extended by transport delay"),
            "expired-result": ("-or[DateTime]::UtcNow-ge$State.ResultsExpires", "", "CONTROL expired result remained selectable"),
            "connected-save": ("(Get-RouterVPNDNSValue $Reply.Value 'connected')-or", "$false-or", "CONTROL connected Save sent policy mutation"),
            "cancel-adoption": ("if(-not$State.Cancelled-and-not$State.Invalid-and-not$State.Closing){", "if(-not$State.Invalid-and-not$State.Closing){", "CONTROL late complete result after cancellation was adopted"),
            "stale-generation": ("$Job.Generation-ne$State.Generation-or$Job.Captured-cne$State.Request", "$Job.Captured-cne$State.Request", "CONTROL stale HTTP completion mutated replacement generation"),
        }
        for name, (old, new, rejection) in variants.items():
            if source.count(old) != 1:
                raise AssertionError(f"Negative control anchor changed: {name}")
            mutant = directory / (name + ".ps1")
            mutant.write_text(source.replace(old, new), encoding="utf-8")
            run(command + ["-Source", mutant], rejection=rejection)
            print("PASS: rejected broken " + name, flush=True)
        if not args.unit_only:
            for scenario in ("success", "tcp", "tls", "early-close", "owner-close", "draining", "unavailable", "replacement"):
                run_live_case(command, scenario)
            blocked = "$Task=$State.Client.SendAsync($Request,$Cts.Token)"
            if source.count(blocked) != 1:
                raise AssertionError("Synchronous HTTP negative no longer targets the shipping request")
            mutant = directory / "blocked-dispatcher.ps1"
            mutant.write_text(source.replace(blocked, blocked + ";$null=$Task.GetAwaiter().GetResult()"), encoding="utf-8")
            with controller("success") as (url, state):
                run(command + ["-Source", mutant, "-Live", "-BaseUrl", url],
                    rejection="CONTROL live capture starts exact owned request")
                if "dispatcher blocked behind pending HTTP response" not in state.failures or state.dispatcher_pulses:
                    raise AssertionError("Blocked UI negative did not fail at the held response")
            print("PASS: rejected synchronous HTTP blocking the dispatcher", flush=True)
    print("Windows shipping DNS measurements, resolver staging, explicit Save and drain ownership: PASS", flush=True)


if __name__ == "__main__":
    main()
