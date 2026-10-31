#!/usr/bin/env python3
"""Check that first-launch diagnostics preserve the actual launch contract."""
from pathlib import Path
import argparse
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("first_ui_diagnostic", ROOT / "deploy/diagnose_windows_ui_startup.py")
DIAGNOSTIC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DIAGNOSTIC)


class FirstLaunchDiagnostic(unittest.TestCase):
    def test_instrumentation_only_adds_fixed_timing_lines(self):
        copies = DIAGNOSTIC.instrumented_scripts()
        self.assertEqual(len(copies), 3)
        stages = set()
        for name, raw in copies.items():
            if name.endswith('ControllerTransport.psm1'):
                before, after = DIAGNOSTIC.lookup_observers()
                self.assertEqual(1, raw.count(before.encode()))
                self.assertEqual(1, raw.count(after.encode()))
                raw = raw.replace(before.encode(), b'', 1).replace(after.encode(), b'', 1)
            lines = raw.splitlines(keepends=True)
            original = (ROOT / name).read_bytes()
            kept = []
            for line in lines:
                if DIAGNOSTIC.PREFIX.encode() in line:
                    self.assertTrue(line.lstrip().startswith(b"[Console]::Error.WriteLine('"))
                    self.assertTrue(line.rstrip().endswith(b"[DateTime]::UtcNow.Ticks)"))
                    stages.add(line.decode().split(DIAGNOSTIC.PREFIX + " ", 1)[1].split(" ticks=", 1)[0])
                else:
                    kept.append(line)
            self.assertEqual(b"".join(kept), original)
        self.assertTrue({"app-script-entered", "tray-script-entered", "module-entered", "initialize-entered",
                         "framework-http-begin", "framework-http-complete", "transport-compile-begin",
                         "transport-compile-complete", "pipe-connect-begin", "pipe-connect-complete"}.issubset(stages))

    def test_lookup_observers_only_observe_the_fixed_command(self):
        before, after = DIAGNOSTIC.lookup_observers()
        self.assertEqual(2, before.count("if($Sender-ceq'Add-Type')"))
        for forbidden in ('Get-Command', 'Import-Module', 'Add-Type -', '$Lookup.Command=', '$Lookup.StopSearch='):
            self.assertNotIn(forbidden, before + after)
        self.assertIn('if($RouterVPNDiagnosticCaptured)', after)
        self.assertIn('PreCommandLookupAction=$RouterVPNDiagnosticPre', after)
        self.assertIn('PostCommandLookupAction=$RouterVPNDiagnosticPost', after)

    def test_changed_initializer_fails_instead_of_tracing_another_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("App.ps1", "Tray.ps1", "ControllerTransport.psm1"):
                relative = "client/RouterVPN-Windows-" + name
                target = root / relative
                target.parent.mkdir(exist_ok=True)
                raw = (ROOT / relative).read_bytes()
                if name.endswith("psm1"):
                    raw = raw.replace(b"        Add-Type @Compile", b"        Add-Type @DifferentCompile")
                target.write_bytes(raw)
            with patch.object(DIAGNOSTIC, "ROOT", root), self.assertRaisesRegex(ValueError, "exact production boundary"):
                DIAGNOSTIC.instrumented_scripts()

    def test_marker_cannot_include_arguments_or_dynamic_input(self):
        for value in ("", "private path", "stage'", "stage\n", "$env:PATH", "123"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                DIAGNOSTIC.marker(value)


def execute_hook_probe(powershell):
    """Optional isolated semantic probe, never a warm-up in the first-UI job."""
    before, after = DIAGNOSTIC.lookup_observers()
    probe = r"""
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2
function Invoke-ObservedBody([object]$Invocation,[scriptblock]$Body){
BEFORE
    & $Body
AFTER
}
function Assert-Probe([bool]$Condition,[string]$Label){if(-not$Condition){throw $Label}}
$Actual=$ExecutionContext.InvokeCommand
$SavedPre=$Actual.PreCommandLookupAction
$SavedPost=$Actual.PostCommandLookupAction
try{
    $Actual.PreCommandLookupAction=$null
    $Actual.PostCommandLookupAction=$null
    $Original=[InvalidOperationException]::new('original execution failure')
    $Value=Invoke-ObservedBody $Actual {Add-Type -AssemblyName System.Net.Http;'original result'}
    Assert-Probe ($Value-ceq'original result') 'observer changed successful execution'
    Assert-Probe ($null-eq$Actual.PreCommandLookupAction-and$null-eq$Actual.PostCommandLookupAction) 'observer retained a hook after success'
    try{Invoke-ObservedBody $Actual {throw $Original};throw 'accepted failed execution'}catch{Assert-Probe ([Object]::ReferenceEquals($_.Exception,$Original)) 'observer replaced original failure'}
    Assert-Probe ($null-eq$Actual.PreCommandLookupAction-and$null-eq$Actual.PostCommandLookupAction) 'observer retained a hook after failure'
    $Existing=[System.EventHandler[System.Management.Automation.CommandLookupEventArgs]]{param($Sender,$Lookup)}
    $Actual.PreCommandLookupAction=$Existing
    $Value=Invoke-ObservedBody $Actual {'preserved existing observer'}
    Assert-Probe ($Value-ceq'preserved existing observer'-and[Object]::ReferenceEquals($Existing,$Actual.PreCommandLookupAction)) 'observer replaced an existing hook'
    $Actual.PreCommandLookupAction=$null
    $Missing=[PSCustomObject]@{}
    $Value=Invoke-ObservedBody $Missing {'unsupported hook still executes'}
    Assert-Probe ($Value-ceq'unsupported hook still executes') 'unsupported API changed execution'
    try{Invoke-ObservedBody $Missing {throw $Original};throw 'accepted failed unsupported execution'}catch{Assert-Probe ([Object]::ReferenceEquals($_.Exception,$Original)) 'unsupported API replaced original failure'}
    $script:ProbePre=$null
    $script:ProbeFailedWrites=0
    $Partial=[PSCustomObject]@{}
    Add-Member -InputObject $Partial -MemberType ScriptProperty -Name PreCommandLookupAction -Value {$script:ProbePre} -SecondValue {param($Value);$script:ProbePre=$Value}
    Add-Member -InputObject $Partial -MemberType ScriptProperty -Name PostCommandLookupAction -Value {$null} -SecondValue {param($Value);$script:ProbeFailedWrites++;throw 'diagnostic setter failed'}
    try{Invoke-ObservedBody $Partial {throw $Original};throw 'accepted failed partial execution'}catch{Assert-Probe ([Object]::ReferenceEquals($_.Exception,$Original)) 'partial setup or restoration replaced original failure'}
    Assert-Probe ($null-eq$script:ProbePre-and$script:ProbeFailedWrites-eq2) 'partial hook was not restored after failed setup'
    $SavedError=[Console]::Error
    $ClosedWriter=[IO.StreamWriter]::new([IO.MemoryStream]::new())
    $ClosedWriter.Dispose()
    try{
        [Console]::SetError($ClosedWriter)
        try{Invoke-ObservedBody $Actual {Add-Type -AssemblyName System.Net.Http;throw $Original};throw 'accepted failed diagnostic output'}catch{Assert-Probe ([Object]::ReferenceEquals($_.Exception,$Original)) 'failed observer output replaced original failure'}
    }finally{[Console]::SetError($SavedError)}
    Assert-Probe ($null-eq$Actual.PreCommandLookupAction-and$null-eq$Actual.PostCommandLookupAction) 'failed observer output retained hooks'
}finally{
    $Actual.PreCommandLookupAction=$SavedPre
    $Actual.PostCommandLookupAction=$SavedPost
}
[Console]::WriteLine('PASS lookup observers preserve execution and restore original hooks')
"""
    probe = probe.replace('BEFORE', before.replace('$ExecutionContext.InvokeCommand', '$Invocation'))
    probe = probe.replace('AFTER', after)
    with tempfile.TemporaryDirectory(prefix='routervpn-lookup-observer-probe-') as temporary:
        path = Path(temporary)/'probe.ps1'
        path.write_text(probe, encoding='utf-8')
        environment = dict(os.environ)
        if sys.platform != 'win32':
            environment.update(XDG_CACHE_HOME=str(Path(temporary)/'cache'),
                               XDG_CONFIG_HOME=str(Path(temporary)/'config'),
                               XDG_DATA_HOME=str(Path(temporary)/'data'))
        completed = subprocess.run([str(powershell), '-NoProfile', '-NonInteractive', '-File', str(path)],
                                   capture_output=True, text=True, env=environment, timeout=30)
    if completed.returncode or 'PASS lookup observers preserve execution and restore original hooks' not in completed.stdout:
        raise AssertionError('Lookup observer semantic probe failed:\n'+completed.stdout[-8192:]+completed.stderr[-8192:])
    for stage in ('framework-command-lookup-begin', 'framework-command-lookup-complete'):
        if stage not in completed.stderr:
            raise AssertionError('Actual lookup hook did not execute: '+stage)
    print(completed.stdout.strip())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--powershell', type=Path)
    arguments, test_arguments = parser.parse_known_args()
    if arguments.powershell is not None:
        execute_hook_probe(arguments.powershell)
    unittest.main(argv=[__file__, *test_arguments])
