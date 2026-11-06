#!/usr/bin/env python3
"""Run the exact native provider drain helper against real bounded child pipes."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ProviderJoin(unittest.TestCase):
    def test_original_process_and_reader_join(self):
        raw = (ROOT / "mobile/desktop/external_box_windows_hysteria2_test.go.tmpl").read_text()
        helper = raw[raw.index("func desktopExternalWFPJoinOutput("):raw.index("func (p *desktopExternalWFPReference) close()")]
        test = r'''
func TestOriginalProviderJoin(t *testing.T) {
 if mode := os.Getenv("ROUTERVPN_JOIN_CHILD"); mode != "" {
  switch mode {
  case "trailer": _, _ = os.Stdout.Write(bytes.Repeat([]byte("x"), 128<<10))
  case "overflow": _, _ = os.Stdout.Write(bytes.Repeat([]byte("x"), 512<<10))
  case "failed": os.Exit(7)
  case "stalled": time.Sleep(10*time.Second)
  }
  os.Exit(0)
 }
 for _, mode := range []string{"trailer", "overflow", "failed", "stalled"} {
  t.Run(mode, func(t *testing.T) {
   ctx,cancel := context.WithCancel(context.Background()); defer cancel()
   command := exec.CommandContext(ctx,os.Args[0],"-test.run=^TestOriginalProviderJoin$")
   command.Env=append(os.Environ(),"ROUTERVPN_JOIN_CHILD="+mode,"GORACE=atexit_sleep_ms=0")
   output,child,err:=os.Pipe(); if err!=nil {t.Fatal(err)}
   command.Stdout=child
   if err=command.Start();err!=nil {t.Fatal(err)}
   _=child.Close()
   done:=make(chan error,1); go func(){done<-command.Wait()}()
   err=desktopExternalWFPJoinOutput(bufio.NewReader(output),output.Close,done,cancel,2*time.Second)
   _=output.Close()
   if (mode=="trailer")!=(err==nil) {t.Fatalf("%s result: %v",mode,err)}
   if command.ProcessState==nil {t.Fatal("original child was not joined")}
  })
 }
}
func TestBoundedDiagnostics(t *testing.T){
 var d desktopExternalWFPDiagnostics
 value:=bytes.Repeat([]byte("x"),128<<10)
 if n,e:=d.Write(value);n!=len(value)||e!=nil{t.Fatal(n,e)}
 if len(d.data)!=64<<10 || !d.overflow || !strings.Contains(d.String(),"exceeded bound"){t.Fatal("diagnostics unbounded")}
}
'''
        with tempfile.TemporaryDirectory(prefix="routervpn-provider-join-") as tmp:
            path = Path(tmp)
            (path / "go.mod").write_text("module providerjoin\n\ngo 1.24.13\n")
            (path / "join_test.go").write_text('package providerjoin\nimport("bufio";"bytes";"context";"errors";"io";"os";"os/exec";"strings";"sync";"testing";"time")\n' + helper + test)
            env = dict(os.environ, GOMAXPROCS="2", GOWORK="off", GOFLAGS="")
            compiler = shutil.which("go")
            host_os, host_arch = subprocess.check_output([compiler, "env", "GOHOSTOS", "GOHOSTARCH"], env=env, text=True, timeout=15).split()
            race = [] if (host_os, host_arch) == ("windows", "arm64") else ["-race"]
            env.update(GOOS=host_os, GOARCH=host_arch, CGO_ENABLED="1" if race else "0")
            binary = path / ("provider-join.test.exe" if host_os == "windows"
                             else "provider-join.test")
            print("Provider join phase=compile", flush=True)
            subprocess.run(
                [compiler, "test", "-c", *race, "-p=1", "-o", str(binary), "."],
                cwd=path, env=env, check=True, timeout=180)
            print("Provider join phase=execute", flush=True)
            subprocess.run(
                [str(binary), "-test.count=1", "-test.timeout=15s", "-test.v"],
                cwd=path, env=env, check=True, timeout=60)


if __name__ == "__main__":
    unittest.main()
