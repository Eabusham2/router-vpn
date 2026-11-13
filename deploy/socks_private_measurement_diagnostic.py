#!/usr/bin/env python3
"""Failure-only, reversible diagnostics for the unchanged private measurement path."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path

PROJECTION = "experimental/libbox/routervpn/hopmeasure/measure.go"
MARKER = "\n// socksPrivateDiagnostic is supplied only by the trusted failure diagnostic overlay.\n"
RECORDER = r'''
// socksPrivateDiagnostic is supplied only by the trusted failure diagnostic overlay.
func socksPrivateDiagnosticCaller(ctx context.Context) error {
 if ctx == nil { return nil }
 return ctx.Err()
}
func socksPrivateDiagnosticClass(err error) string {
 if err == nil { return "none" }
 if errors.Is(err, context.DeadlineExceeded) { return "deadline" }
 if errors.Is(err, context.Canceled) { return "cancelled" }
 if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) { return "closed" }
 var timeout net.Error
 if errors.As(err, &timeout) && timeout.Timeout() { return "timeout" }
 return "rejected"
}
func socksPrivateDiagnostic(operation, stage, role string, result, cause, caller error, elapsed time.Duration) {
 if result == nil { return }
 // A custom error formatter/classifier must never replace the original failure.
 defer func() { _ = recover() }()
 switch role { case "entry", "intermediate", "exit": default: role = "other" }
 fmt.Fprintf(os.Stderr, "SOCKS_PRIVATE_DIAGNOSTIC operation=%s stage=%s role=%s result=%s cause=%s caller=%s elapsed_us=%d\n",
  operation, stage, role, socksPrivateDiagnosticClass(result), socksPrivateDiagnosticClass(cause),
  socksPrivateDiagnosticClass(caller), elapsed.Microseconds())
}
'''
REPLACEMENTS = (
 ('\t"errors"\n', '\t"errors"\n\t"fmt"\n\t"os"\n'),
 ('func (s *Service) requestWithActivity(ctx context.Context, h Hop, path string, size int, upload bool, activity *transferActivity) (*http.Response, measurementInstant, *http.Client, error) {\n',
  'func (s *Service) requestWithActivity(ctx context.Context, h Hop, path string, size int, upload bool, activity *transferActivity) (diagnosticResponse *http.Response, diagnosticStart measurementInstant, diagnosticClient *http.Client, diagnosticError error) {\n'
  '\tdiagnosticStarted, diagnosticStage := time.Now(), "prepare"\n\tvar diagnosticCause error\n'
  '\tdefer func() { if diagnosticError != nil { socksPrivateDiagnostic("request", diagnosticStage, h.Role, diagnosticError, diagnosticCause, socksPrivateDiagnosticCaller(ctx), time.Since(diagnosticStarted)) } }()\n'),
 ('\tstart, err := readMeasurementClock()\n\tif err != nil {\n\t\tclient.CloseIdleConnections()',
  '\tdiagnosticStage = "request-clock"\n\tstart, err := readMeasurementClock()\n\tif err != nil {\n\t\tclient.CloseIdleConnections()'),
 ('\tresp, err := client.Do(r)\n\tif err != nil {\n\t\tclient.CloseIdleConnections()',
  '\tdiagnosticStage = "round-trip"\n\tresp, err := client.Do(r)\n\tif err != nil {\n\t\tdiagnosticCause = err\n\t\tclient.CloseIdleConnections()'),
 ('\tif resp.StatusCode != 200 || resp.Header.Get("Content-Encoding") != "" && resp.Header.Get("Content-Encoding") != "identity" {',
  '\tdiagnosticStage = "response"\n\tif resp.StatusCode != 200 || resp.Header.Get("Content-Encoding") != "" && resp.Header.Get("Content-Encoding") != "identity" {'),
 ('func (s *Service) prove(parent context.Context, h Hop) (float64, error) {\n',
  'func (s *Service) prove(parent context.Context, h Hop) (diagnosticLatency float64, diagnosticError error) {\n'),
 ('\tctx, cancel := context.WithTimeout(parent, 2*time.Second)\n\tdefer cancel()\n\tresp, start, client, err := s.request(ctx, h, "/health", 0, false)',
  '\tctx, cancel := context.WithTimeout(parent, 2*time.Second)\n\tdefer cancel()\n'
  '\tdiagnosticStarted, diagnosticStage := time.Now(), "request"\n'
  '\tdefer func() { if diagnosticError != nil { socksPrivateDiagnostic("prove", diagnosticStage, h.Role, diagnosticError, nil, socksPrivateDiagnosticCaller(ctx), time.Since(diagnosticStarted)) } }()\n'
  '\tresp, start, client, err := s.request(ctx, h, "/health", 0, false)'),
 ('\tdata, err := io.ReadAll(io.LimitReader(resp.Body, 4097))\n\tif err != nil || len(data) > 4096 {',
  '\tdiagnosticStage = "body"\n\tdata, err := io.ReadAll(io.LimitReader(resp.Body, 4097))\n\tif err != nil || len(data) > 4096 {'),
 ('\tif strictJSON(data, &value) != nil || !value.OK || value.Node != h.Proof || value.Proof != "router-vpn-private-agent-v1" {',
  '\tdiagnosticStage = "identity"\n\tif strictJSON(data, &value) != nil || !value.OK || value.Node != h.Proof || value.Proof != "router-vpn-private-agent-v1" {'),
 ('\tif err = s.valid(ctx); err != nil {\n\t\treturn 0, err\n\t}\n\tfinish, err := readMeasurementClock()',
  '\tdiagnosticStage = "owner"\n\tif err = s.valid(ctx); err != nil {\n\t\treturn 0, err\n\t}\n\tdiagnosticStage = "result-clock"\n\tfinish, err := readMeasurementClock()'),
)

def apply(original: str) -> str:
    if "socksPrivateDiagnostic" in original:
        raise ValueError("Diagnostic already present in original source")
    changed = original
    for before, after in REPLACEMENTS:
        if changed.count(before) != 1:
            raise ValueError("Original private measurement diagnostic seam moved")
        changed = changed.replace(before, after)
    changed += RECORDER
    if restore(changed) != original:
        raise ValueError("Diagnostic changed an original statement")
    return changed

def restore(changed: str) -> str:
    if not changed.endswith(RECORDER):
        raise ValueError("Original diagnostic recorder missing or changed")
    original = changed[:-len(RECORDER)]
    for before, after in reversed(REPLACEMENTS):
        if original.count(after) != 1:
            raise ValueError("Diagnostic annotation missing, duplicated or changed")
        original = original.replace(after, before)
    return original

def prepare(core: Path, directory: Path) -> dict:
    core = Path(core).resolve(strict=True)
    directory = Path(directory).absolute()
    original = core / PROJECTION
    if original.is_symlink() or not original.is_file():
        raise ValueError("Original private measurement source absent")
    if directory.exists() or directory.is_symlink() or core == directory or core in directory.parents:
        raise ValueError("Diagnostic files need a fresh directory outside the native source")
    text = original.read_text()
    changed = apply(text)
    directory.mkdir(mode=0o700)
    replacement = directory / "measure.go"
    replacement.write_text(changed)
    overlay = directory / "overlay.json"
    overlay.write_text(json.dumps({"Replace": {str(original): str(replacement)}}) + "\n")
    receipt = dict(schema=1, kind="failure-only-private-measurement-diagnostic",
        source=str(original), source_sha256=hashlib.sha256(text.encode()).hexdigest(),
        replacement=str(replacement), replacement_sha256=hashlib.sha256(changed.encode()).hexdigest(),
        overlay=str(overlay), overlay_sha256=hashlib.sha256(overlay.read_bytes()).hexdigest(),
        original_return_statements_preserved=True, original_deadlines_preserved=True,
        acceptance_changed=False, public_native_admission=False)
    (directory / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt
