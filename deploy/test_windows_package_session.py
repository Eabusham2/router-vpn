#!/usr/bin/env python3
"""Exercise the real package-check adapter, with explicit modeled app children.

This is not a native Session or UAC test. On Windows the unchanged file-identity
P/Invoke runs; other hosts substitute only that unavailable API with a path
comparison model. Dispatch, exit status, state, relocation and sharing checks
remain the actual PowerShell source, and the launched child is a real process.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT/'client/test-windows-package-session.ps1'
GUARD = "if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Packaged Session proof requires actual Windows.' }"
TYPE = re.compile(r"Add-Type -TypeDefinition @'\n(.*?)\n'@", re.S)
MODEL = r'''using System;
using System.IO;
namespace RouterVPN {
public static class PackageSessionIdentity {
    public static void RequireSame(string actual, string expected, bool directory) {
        bool exists=directory ? Directory.Exists(actual) : File.Exists(actual);
        if(!exists || !String.Equals(Path.GetFullPath(actual),Path.GetFullPath(expected),StringComparison.Ordinal))
            throw new InvalidOperationException("Package Session selected another physical file or directory.");
    }
}}
'''
FIXTURE = r'''package main
import (
    "encoding/json"
    "fmt"
    "os"
    "path/filepath"
    "strings"
)
func fail(code int, err error) { fmt.Fprintln(os.Stderr, err); os.Exit(code) }
func main() {
    if len(os.Args)!=2 || os.Args[1]!="--self-test" { fail(91,fmt.Errorf("wrong public arguments")) }
    executable,err:=os.Executable();if err!=nil {fail(92,err)}
    root:=filepath.Dir(executable)
    cwd,err:=os.Getwd();if err!=nil {fail(92,err)}
    want,err:=os.Stat(root);if err!=nil {fail(92,err)}
    got,err:=os.Stat(cwd);if err!=nil || !os.SameFile(want,got) {fail(93,fmt.Errorf("wrong child working directory"))}
    record:=os.Getenv("ROUTERVPN_PACKAGE_FIXTURE_RECORD")
    previous,err:=os.ReadFile(record);if err!=nil && !os.IsNotExist(err) {fail(94,err)}
    attempt:=strings.Count(string(previous),"\n")+1
    file,err:=os.OpenFile(record,os.O_WRONLY|os.O_APPEND|os.O_CREATE,0600);if err!=nil {fail(94,err)}
    err=json.NewEncoder(file).Encode(map[string]any{"args":os.Args[1:],"cwd":cwd,"root":root,"pid":os.Getpid(),"attempt":attempt})
    closed:=file.Close();if err!=nil || closed!=nil {fail(94,fmt.Errorf("fixture record write failed"))}
    portable:=strings.Contains(strings.ToLower(filepath.Base(executable)),"portable")
    packageRoot,data:=root,root
    if portable {packageRoot=filepath.Join(root,"App","RouterVPN");data=filepath.Join(root,"Data")}
    if err:=os.MkdirAll(data,0700);err!=nil {fail(95,err)}
    mode:=os.Getenv("ROUTERVPN_PACKAGE_FIXTURE_CASE")
    profile:=filepath.Join(data,"routers.json")
    if _,err:=os.Stat(profile);os.IsNotExist(err) {if err:=os.WriteFile(profile,[]byte("{\"routers\":[]}\n"),0600);err!=nil {fail(95,err)}} else if err!=nil {fail(95,err)}
    if mode=="changed-routers" && attempt==2 {if err:=os.WriteFile(profile,[]byte("{\"routers\":[],\"changed\":true}\n"),0600);err!=nil {fail(95,err)}}
    config:=map[string]string{"modes_file":filepath.Join(packageRoot,"modes.json"),"scripts_dir":filepath.Join(packageRoot,"modes"),"profiles_file":profile,"state_file":filepath.Join(data,"state.json")}
    if mode=="wrong-identity" {config["modes_file"]=filepath.Join(packageRoot,"another-modes.json")}
    if mode=="relative-portable" {config["modes_file"]="modes.json"}
    if mode=="relative-state" {config["state_file"]="state.json"}
    if mode=="wrong-state" {config["state_file"]=filepath.Join(data,"another-state.json")}
    if mode!="stale-relocation" || attempt==1 {
        body,err:=json.Marshal(config);if err!=nil {fail(95,err)}
        if err:=os.WriteFile(filepath.Join(data,"client.json"),body,0600);err!=nil {fail(95,err)}
    }
    if mode=="exit37" {fail(37,fmt.Errorf("bounded-fixture-exit-witness"))}
}
'''


def require(value, message):
    if not value:
        raise AssertionError(message)


def execute(command, *, environment, cwd, timeout=90):
    return subprocess.run(command, env=environment, cwd=cwd, capture_output=True,
                          text=True, timeout=timeout)


def check(shell):
    original=SOURCE.read_text(encoding='utf-8')
    original_hash=hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    found=TYPE.search(original)
    require(found is not None and original.count(GUARD)==1,
            'Packaged identity API or actual Windows guard changed')
    environment=dict(os.environ, GOWORK='off', GOTOOLCHAIN='local')
    result=execute(['go','test','-count=1','./internal/windowsapp','-run',
                    '^TestWindowsPublicEntriesUseOwnedMain$'],environment=environment,cwd=ROOT)
    require(result.returncode==0,'Public wrapper ownership regression failed:\n'+result.stdout+result.stderr)
    with tempfile.TemporaryDirectory(prefix='routervpn-package-adapter-') as temporary:
        root=Path(temporary)
        # Compile the unchanged C# declaration on every host. Its actual native
        # calls run only on Windows; this compile is not native API evidence.
        parse=root/'parse.ps1'
        parse.write_text("$ErrorActionPreference='Stop'\n$tokens=$null;$errors=$null\n"
                         "[void][Management.Automation.Language.Parser]::ParseFile($args[0],[ref]$tokens,[ref]$errors)\n"
                         "if($errors.Count){throw ($errors|Out-String)}\n"+
                         "Add-Type -TypeDefinition @'\n"+found.group(1)+"\n'@\n", encoding='utf-8')
        result=execute([shell,'-NoProfile','-NonInteractive','-File',str(parse),str(SOURCE)],
                       environment=environment,cwd=root)
        require(result.returncode==0,'Actual package helper parse/type compile failed:\n'+result.stdout+result.stderr)
        source=root/'fixture.go';source.write_text(FIXTURE,encoding='utf-8')
        child=root/'fixture.exe'
        command=['go','build','-trimpath']
        if os.name=='nt':
            command+=['-ldflags=-H=windowsgui']
        result=execute(command+['-o',str(child),str(source)],environment=environment,cwd=ROOT)
        require(result.returncode==0,'Package fixture compile failed:\n'+result.stdout+result.stderr)
        adapter=original
        if os.name!='nt':
            adapter=adapter.replace(GUARD,'# Explicit non-Windows adapter fixture; native acceptance remains separate.',1)
            adapter=TYPE.sub(lambda _:"Add-Type -TypeDefinition @'\n"+MODEL+"\n'@",adapter,count=1)

        def trial(label, *, portable=False, relocate=False, mode='', missing='', held=False, text=None):
            owned=root/label;owned.mkdir()
            package=owned/'Original package with spaces';package.mkdir()
            installed=package/'App/RouterVPN' if portable else package
            (installed/'client').mkdir(parents=True)
            (installed/'modes').mkdir()
            for name,body in {
                'modes.json':'{}', 'another-modes.json':'{}',
                'logical-modes.json':json.dumps(list(range(15 if mode=='catalog15' else 16))),
                'router-vpn-client.exe':'explicit process fixture, not a controller',
                'client/RouterVPN-Windows-App.ps1':'# modeled UI fixture',
                'client/RouterVPN-Windows-Tray.ps1':'# modeled tray fixture',
                'client/RouterVPN-Windows-ControllerTransport.cs':'// modeled transport fixture',
            }.items():
                (installed/name).write_text(body,encoding='utf-8')
            launcher=package/('RouterVPNPortable.exe' if portable else 'RouterVPN.exe')
            shutil.copy2(child,launcher)
            if missing=='launcher':
                launcher.unlink()
            elif missing:
                (installed/missing).unlink()
            script=owned/'adapter.ps1';script.write_text(adapter if text is None else text,encoding='utf-8')
            record=owned/'children.jsonl'
            command=[shell,'-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(script),'-Root',str(package)]
            if portable:
                command+=['-Portable']
            moved=owned/'Relocated package with spaces'
            if relocate:
                command+=['-RelocateTo',str(moved)]
            if held:
                driver=owned/'held.ps1'
                driver.write_text("$ErrorActionPreference='Stop'\n"
                                  "$pin=[IO.File]::Open($args[0],[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)\n"
                                  "try { & $args[1] -Root $args[2] } finally { $pin.Dispose() }\n",encoding='utf-8')
                command=[shell,'-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(driver),str(installed/'router-vpn-client.exe'),str(script),str(package)]
            result=execute(command,environment=dict(environment,ROUTERVPN_PACKAGE_FIXTURE_RECORD=str(record),ROUTERVPN_PACKAGE_FIXTURE_CASE=mode),cwd=owned)
            events=[json.loads(line) for line in record.read_text(encoding='utf-8').splitlines()] if record.exists() else []
            require(len(events)==(0 if missing=='launcher' else (2 if relocate else 1)),
                    label+': adapter omitted or duplicated actual child dispatch:\n'+result.stdout+result.stderr)
            for index,event in enumerate(events):
                expected=moved if index else package
                require(event['args']==['--self-test'] and event['attempt']==index+1 and type(event['pid']) is int and event['pid']>0,
                        label+': actual child argv/identity changed')
                require(os.path.normcase(event['cwd'])==os.path.normcase(str(expected)) and
                        os.path.normcase(event['root'])==os.path.normcase(str(expected)),
                        label+': actual child escaped its captured package directory')
            return result

        for label,options in [('installed',{}),('portable-relocation',{'portable':True,'relocate':True})]:
            result=trial(label,**options)
            require(result.returncode==0,label+' package adapter failed:\n'+result.stdout+result.stderr)
        negatives=[
            ('failed-child',{'mode':'exit37'},'self-test failed: 37'),
            ('wrong-file',{'mode':'wrong-identity'},'selected another physical'),
            ('relative-portable',{'portable':True,'mode':'relative-portable'},'uncaptured relative'),
            ('relative-state',{'portable':True,'mode':'relative-state'},'uncaptured relative state path'),
            ('wrong-state',{'mode':'wrong-state'},'private state filename'),
            ('catalog15',{'mode':'catalog15'},'sixteen logical choices'),
            ('stale-relocation',{'portable':True,'relocate':True,'mode':'stale-relocation'},'RequireSame'),
            ('changed-routers',{'portable':True,'relocate':True,'mode':'changed-routers'},'replaced its private router store'),
            ('missing-code',{'missing':'client/RouterVPN-Windows-Tray.ps1'},'Open'),
            ('held-code',{'held':True},'Open'),
            ('missing-launcher',{'missing':'launcher'},'no adjacent native launcher'),
        ]
        for label,options,witness in negatives:
            result=trial(label,**options)
            require(result.returncode!=0 and witness in result.stdout+result.stderr,
                    label+' did not reach its intended rejection:\n'+result.stdout+result.stderr)
        mutants=[
            ('ignore-exit','if(-not $process.HasExited -or $process.ExitCode -ne 0)','if($false)',{'mode':'exit37'}),
            ('ignore-file-identity','[RouterVPN.PackageSessionIdentity]::RequireSame($actual,[string]$item[1],[bool]$item[2])','$null=$actual',{'mode':'wrong-identity'}),
            ('ignore-router-replacement','if($relocatedRouters -cne $routers)','if($false)',{'portable':True,'relocate':True,'mode':'changed-routers'}),
            ('ignore-code-pins',"$stream=[IO.File]::Open((Join-Path $paths.Package $relative),[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)","$stream=New-Object IO.MemoryStream",{'held':True}),
        ]
        for label,before,after,options in mutants:
            require(adapter.count(before)==1,'Package adapter mutant drifted: '+label)
            result=trial(label,text=adapter.replace(before,after,1),**options)
            require(result.returncode==0,'Package adapter mutant did not expose the intended lost rejection: '+label+'\n'+result.stdout+result.stderr)
    require(hashlib.sha256(SOURCE.read_bytes()).hexdigest()==original_hash,'Adapter fixture changed the shipping script')
    print('Packaged Session adapter: 2 actual-process positives, 11 rejection cases and 4 executed source controls PASS ('+shell+'; '+('native Windows file identity' if os.name=='nt' else 'explicit non-Windows file-identity model')+')')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--shell',default='pwsh')
    args=parser.parse_args()
    shell=shutil.which(args.shell)
    require(shell is not None,'Required PowerShell is unavailable: '+args.shell)
    require(shutil.which('go') is not None,'Go fixture compiler is required')
    check(shell)


if __name__=='__main__':
    main()
