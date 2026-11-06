#!/usr/bin/env python3
"""Run the exact native provider drain helper against real bounded child pipes."""
from pathlib import Path
import os
import re
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




class OpenVPNIPC(unittest.TestCase):
    def test_original_serialized_exchange(self):
        raw = (ROOT / "mobile/desktop/external_box_openvpn_reference_test.go.tmpl").read_text()
        records = raw[raw.index("type desktopOpenVPNCompositionPeerInput struct {"):raw.index("func desktopOpenVPNCompositionProviderBox(")]
        helper = raw[raw.index("type desktopOpenVPNCompositionProcess struct {"):raw.index("type desktopOpenVPNCompositionFixture struct {")]
        test = r'''
func TestOpenVPNIPCChild(t *testing.T) {
 mode := os.Getenv("ROUTERVPN_IPC_CHILD")
 if mode == "" { return }
 fmt.Fprintln(os.Stderr, "ready")
 if mode == "write-blocked" { time.Sleep(30*time.Second); return }
 reader := json.NewDecoder(os.Stdin)
 count := int32(0)
 for {
  var request json.RawMessage
  if err := reader.Decode(&request); err != nil {
   if errors.Is(err, io.EOF) { return }
   t.Fatal("child input failed")
  }
  fmt.Fprintln(os.Stderr, "entered")
  switch mode {
  case "read-blocked": time.Sleep(30*time.Second); return
  case "slow":
   if count == 0 {
    for {
     if _,err:=os.Stat(os.Getenv("ROUTERVPN_IPC_RELEASE"));err==nil{break}
     time.Sleep(time.Millisecond)
    }
   }
  case "malformed": fmt.Fprintln(os.Stdout, "{}"); continue
  case "oversized": fmt.Fprintln(os.Stdout, strings.Repeat("x", (16<<10)+2)); continue
  }
  count++
  reply := desktopOpenVPNCompositionPeerReply{Schema:1, Network:"udp", Remote:"127.0.0.1:12001", UnavailableRemote:"127.0.0.1:12002", AppID:[]byte{1,2}, PublicAttempts:count}
  if mode == "changed" { reply.Remote = "127.0.0.1:12003" }
  if err := json.NewEncoder(os.Stdout).Encode(reply); err != nil { return }
 }
}
func ipcNotice(t *testing.T, reader *bufio.Reader, file io.Closer, wanted string) {
 t.Helper()
 result := make(chan string, 1)
 go func() { line, _ := reader.ReadString('\n'); result <- strings.TrimSpace(line) }()
 select {
 case value := <-result:
  if value != wanted { t.Fatal("child phase changed") }
 case <-time.After(3*time.Second):
  _ = file.Close()
  select { case <-result: case <-time.After(time.Second): t.Error("notice reader unjoined") }
  t.Fatal("child phase missing")
 }
}
func ipcProcess(t *testing.T, mode string) (*desktopOpenVPNCompositionProcess, *bufio.Reader, io.Closer) {
 t.Helper()
 ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
 p := &desktopOpenVPNCompositionProcess{address:"127.0.0.1", cancel:cancel, done:make(chan struct{}), permit:make(chan struct{},1), closeDone:make(chan struct{})}
 p.permit <- struct{}{}
 p.command = exec.CommandContext(ctx, os.Args[0], "-test.run=^TestOpenVPNIPCChild$")
 p.command.Env = append(os.Environ(), "ROUTERVPN_IPC_CHILD="+mode, "ROUTERVPN_IPC_RELEASE="+t.TempDir()+"/release", "GORACE=atexit_sleep_ms=0")
 var err error
 p.input, err = p.command.StdinPipe()
 if err != nil { cancel(); t.Fatal(err) }
 var writer *os.File
 p.output, writer, err = os.Pipe()
 if err != nil { cancel(); _=p.input.Close(); t.Fatal(err) }
 stderr, err := p.command.StderrPipe()
 if err != nil { cancel(); _=p.input.Close(); _=p.output.Close(); _=writer.Close(); t.Fatal(err) }
 p.reader = bufio.NewReaderSize(p.output, (16<<10)+1)
 p.command.Stdout = writer
 if err := p.command.Start(); err != nil { cancel(); _=p.input.Close(); _=p.output.Close(); _=writer.Close(); _=stderr.Close(); t.Fatal(err) }
 _ = writer.Close()
 go func(){ p.waitErr=p.command.Wait(); close(p.done) }()
 t.Cleanup(func(){ _=p.close(); _=stderr.Close() })
 notices := bufio.NewReader(stderr)
 ipcNotice(t,notices,stderr,"ready")
 return p,notices,stderr
}
func ipcJoined(t *testing.T,p *desktopOpenVPNCompositionProcess) {
 t.Helper()
 p.mu.Lock(); worker, stopped := p.worker,p.stopped; p.mu.Unlock()
 if !stopped { t.Fatal("failed exchange did not retire reader") }
 if worker == nil { t.Fatal("exchange never entered original worker") }
 select {case <-worker: default: t.Fatal("original IPC worker still running")}
 select {case <-p.done: default: t.Fatal("original process still running")}
 original := p.command
 ctx,cancel := context.WithTimeout(context.Background(),time.Second); defer cancel()
 if _,err:=p.observeContext(ctx,"stats"); !errors.Is(err,net.ErrClosed) { t.Fatal("retired reader reused",err) }
 if p.command != original { t.Fatal("original process replaced") }
 first,second:=p.close(),p.close()
 if fmt.Sprint(first)!=fmt.Sprint(second) {t.Fatal("close result changed")}
}
func TestOpenVPNIPC(t *testing.T) {
 t.Run("normal-and-idempotent-close",func(t *testing.T){
  p:=desktopOpenVPNReferenceStart(t,desktopOpenVPNCompositionPeerInput{Schema:1,Network:"udp"},"127.0.0.1",func(ctx context.Context)*exec.Cmd{
   command:=exec.CommandContext(ctx,os.Args[0],"-test.run=^TestOpenVPNIPCChild$")
   command.Env=append(os.Environ(),"ROUTERVPN_IPC_CHILD=normal")
   return command
  })
  if p.initial.PublicAttempts!=1 {t.Fatal("initial receipt failed")}
  if reply:=p.observe(t,"stats");reply.PublicAttempts!=2 {t.Fatal("serialized receipt failed")}
  if err:=p.close();err!=nil {t.Fatal(err)}
  if err:=p.close();err!=nil {t.Fatal(err)}
  ipcJoined(t,p)
 })
 t.Run("queued-cancel-preserves-active",func(t *testing.T){
  p,notices,stderr:=ipcProcess(t,"slow")
  ctx,cancel:=context.WithTimeout(context.Background(),3*time.Second);defer cancel()
  result:=make(chan error,1)
  go func(){reply,err:=p.observeContext(ctx,"stats");if err==nil&&reply.PublicAttempts!=1 {err=errors.New("active reply changed")};result<-err}()
  ipcNotice(t,notices,stderr,"entered")
  queued,stop:=context.WithTimeout(context.Background(),50*time.Millisecond);defer stop()
  if _,err:=p.observeContext(queued,"stats");!errors.Is(err,context.DeadlineExceeded){t.Fatal("queued deadline lost",err)}
  p.mu.Lock(); stopped:=p.stopped; p.mu.Unlock()
  if stopped {t.Fatal("queued timeout retired active process")}
  release:=""
  for _,value:=range p.command.Env {
   if strings.HasPrefix(value,"ROUTERVPN_IPC_RELEASE="){release=strings.TrimPrefix(value,"ROUTERVPN_IPC_RELEASE=")}
  }
  if release=="" {t.Fatal("original child release missing")}
  if err:=os.WriteFile(release,[]byte("release"),0600);err!=nil{t.Fatal(err)}
  if err:=<-result;err!=nil{t.Fatal("active exchange killed",err)}
  reply,err:=p.observeContext(ctx,"stats")
  if err!=nil||reply.PublicAttempts!=2{t.Fatal("cancelled waiter wrote or retired original",err)}
  if err:=p.close();err!=nil{t.Fatal(err)}
 })
 t.Run("blocked-read",func(t *testing.T){
  p,notices,stderr:=ipcProcess(t,"read-blocked")
  ctx,cancel:=context.WithTimeout(context.Background(),time.Second);defer cancel()
  result:=make(chan error,1)
  go func(){_,err:=p.observeContext(ctx,"stats");result<-err}()
  ipcNotice(t,notices,stderr,"entered")
  if err:=<-result;!errors.Is(err,context.DeadlineExceeded){t.Fatal("read timeout lost",err)}
  ipcJoined(t,p)
 })
 t.Run("blocked-write",func(t *testing.T){
  p,_,_:=ipcProcess(t,"write-blocked")
  ctx,cancel:=context.WithTimeout(context.Background(),time.Second);defer cancel()
  _,err:=p.exchange(ctx,map[string]string{"large":strings.Repeat("x",2<<20)})
  if !errors.Is(err,context.DeadlineExceeded){t.Fatal("write timeout lost",err)}
  ipcJoined(t,p)
 })
 t.Run("active-close",func(t *testing.T){
  p,notices,stderr:=ipcProcess(t,"read-blocked")
  ctx,cancel:=context.WithTimeout(context.Background(),3*time.Second);defer cancel()
  result:=make(chan error,1)
  go func(){_,err:=p.observeContext(ctx,"stats");result<-err}()
  ipcNotice(t,notices,stderr,"entered")
  closed:=make(chan error,1)
  go func(){closed<-p.close()}()
  select {case err:=<-result: if err==nil{t.Fatal("active close accepted receipt")};case <-time.After(4*time.Second):t.Fatal("active exchange did not join")}
  select {case <-closed:case <-time.After(4*time.Second):t.Fatal("active close did not join")}
  ipcJoined(t,p)
 })
 for _,mode:=range []string{"malformed","oversized","changed"}{
  t.Run(mode,func(t *testing.T){
   p,_,_:=ipcProcess(t,mode)
   p.initial=desktopOpenVPNCompositionPeerReply{Schema:1,Network:"udp",Remote:"127.0.0.1:12001",UnavailableRemote:"127.0.0.1:12002",AppID:[]byte{1,2}}
   ctx,cancel:=context.WithTimeout(context.Background(),time.Second);defer cancel()
   if _,err:=p.observeContext(ctx,"stats");err==nil{t.Fatal("invalid receipt accepted")}
   ipcJoined(t,p)
  })
 }
}
'''
        with tempfile.TemporaryDirectory(prefix="routervpn-openvpn-ipc-") as tmp:
            path = Path(tmp)
            (path / "go.mod").write_text("module openvpnipc\n\ngo 1.24.13\n")
            (path / "ipc_test.go").write_text('package openvpnipc\nimport("bufio";"context";"encoding/json";"errors";"fmt";"io";"net";"net/netip";"os";"os/exec";"reflect";"strings";"sync";"testing";"time")\n' + records + helper + test)
            env = dict(os.environ, GOMAXPROCS="2", GOWORK="off", GOFLAGS="")
            compiler = shutil.which("go")
            host_os, host_arch = subprocess.check_output([compiler, "env", "GOHOSTOS", "GOHOSTARCH"], env=env, text=True, timeout=15).split()
            race = [] if (host_os, host_arch) == ("windows", "arm64") else ["-race"]
            env.update(GOOS=host_os, GOARCH=host_arch, CGO_ENABLED="1" if race else "0")
            binary = path / ("openvpn-ipc.test.exe" if host_os == "windows" else "openvpn-ipc.test")
            print("OpenVPN IPC phase=compile", flush=True)
            subprocess.run([compiler, "test", "-c", *race, "-p=1", "-o", str(binary), "."],
                           cwd=path, env=env, check=True, timeout=180)
            print("OpenVPN IPC phase=execute", flush=True)
            result = subprocess.run([str(binary), "-test.run=^TestOpenVPNIPC$", "-test.count=1", "-test.timeout=30s", "-test.v"],
                                    cwd=path, env=env, capture_output=True, text=True, timeout=60)
            output = result.stdout + result.stderr
            print(output, end="" if output.endswith("\n") else "\n", flush=True)
            required = ["TestOpenVPNIPC", *("TestOpenVPNIPC/" + leaf for leaf in (
                "normal-and-idempotent-close", "queued-cancel-preserves-active",
                "blocked-read", "blocked-write", "active-close", "malformed", "oversized", "changed"))]
            if result.returncode or any(len(re.findall(r"(?m)^[ \t]*--- PASS: " + re.escape(case) + r" \(", output)) != 1 for case in required) or re.search(r"--- FAIL:|--- SKIP:|DATA RACE|panic:|fatal error:|\[build failed\]", output):
                raise AssertionError("Original OpenVPN IPC omitted its complete owned-process contract")


class ProviderImageCopy(unittest.TestCase):
    def test_captured_independent_provider_images(self):
        raw = (ROOT / "mobile/desktop/external_box_windows_hysteria2_test.go.tmpl").read_text()
        helper = raw[raw.index("type desktopExternalWFPImage struct {"):raw.index("func desktopExternalWFPStartReferenceCaptured(")]
        test = r'''
func TestProviderImage(t *testing.T) {
	t.Run("captured-independent-images",func(t *testing.T){
		directory:=t.TempDir()
		source:=filepath.Join(directory,"original.exe")
		want:=bytes.Repeat([]byte("original-private-image"),10000)
		if err:=os.WriteFile(source,want,0700);err!=nil{t.Fatal(err)}
		image,err:=desktopExternalWFPCaptureImage(source)
		if err!=nil{t.Fatal(err)}
		if image.size!=int64(len(want))||image.digest!=sha256.Sum256(want){t.Fatal("source receipt changed")}
		// Later source-path bytes are not silently adopted by the snapshot.
		if err:=os.WriteFile(source,[]byte("replacement"),0700);err!=nil{t.Fatal(err)}
		var infos []os.FileInfo
		for _,name:=range []string{"first.exe","second.exe"}{
			path:=filepath.Join(directory,name)
			owner,err:=image.create(path)
			if err!=nil{t.Fatal(err)}
			if err:=owner.close();err!=nil{t.Fatal(err)}
			raw,err:=os.ReadFile(path)
			if err!=nil||!bytes.Equal(raw,want)||sha256.Sum256(raw)!=image.digest{t.Fatal("copy lost original bytes",err)}
			info,err:=os.Stat(path);if err!=nil{t.Fatal(err)};infos=append(infos,info)
			if duplicate,err:=image.create(path);err==nil||duplicate!=nil{t.Fatal("copy adopted an existing executable")}
			again,err:=os.ReadFile(path);if err!=nil||!bytes.Equal(again,want){t.Fatal("failed exclusive copy changed existing image")}
		}
		if os.SameFile(infos[0],infos[1]){t.Fatal("two providers shared executable file ownership")}
	})
	t.Run("bounded-write-and-retained-close",func(t *testing.T){
		body:=strings.Repeat("x",3*(64<<10)+17)
		image:=&desktopExternalWFPImage{data:body,size:int64(len(body)),digest:sha256.Sum256([]byte(body))}
		writer:=&imageFaultWriter{failClose:true}
		owner,err:=image.write(writer)
		if err==nil||owner==nil||owner.closed||writer.closes!=1{t.Fatal("failed close lost original writer")}
		if writer.max>64<<10||writer.writes!=4||writer.String()!=body{t.Fatal("image copy lost bounded complete writes")}
		if err:=owner.close();err!=nil||!owner.closed||writer.closes!=2{t.Fatal("original close was not retried",err)}
		if err:=owner.close();err!=nil||writer.closes!=2{t.Fatal("acknowledged close repeated")}
	})
	t.Run("failed-copy-never-adopts",func(t *testing.T){
		body:=strings.Repeat("a",70<<10)
		image:=&desktopExternalWFPImage{data:body,size:int64(len(body)),digest:sha256.Sum256([]byte(body))}
		for _,mode:=range []string{"short","write","tamper"}{
			writer:=&imageFaultWriter{mode:mode}
			owner,err:=image.write(writer)
			if err==nil||owner==nil||!owner.closed||writer.closes!=1{t.Fatal("failed copy lost close or returned success",mode)}
			if image.data!=body||image.digest!=sha256.Sum256([]byte(body)){t.Fatal("writer changed immutable cached source")}
		}
		path:=filepath.Join(t.TempDir(),"partial.exe")
		bad:=&desktopExternalWFPImage{data:"partial",size:1}
		owner,err:=bad.create(path)
		if err==nil||owner==nil||!owner.closed{t.Fatal("partial image remained launchable")}
		if err:=os.Remove(path);err!=nil{t.Fatal("failed copy retained its file handle",err)}
	})
}
type imageFaultWriter struct {
	bytes.Buffer
	mode string
	failClose bool
	writes,max,closes int
}
func(w *imageFaultWriter)Write(raw []byte)(int,error){
	w.writes++
	if len(raw)>w.max{w.max=len(raw)}
	if w.mode=="write"{return 0,errors.New("owned write refused")}
	if w.mode=="short"{return w.Buffer.Write(raw[:len(raw)-1])}
	if w.mode=="tamper"{raw[0]^=1}
	return w.Buffer.Write(raw)
}
func(w *imageFaultWriter)Close()error{
	w.closes++
	if w.failClose&&w.closes==1{return errors.New("original close unacknowledged")}
	return nil
}
'''
        with tempfile.TemporaryDirectory(prefix="routervpn-provider-image-") as tmp:
            path = Path(tmp)
            (path / "go.mod").write_text("module providerimage\n\ngo 1.24.13\n")
            (path / "image_test.go").write_text('package providerimage\nimport("bytes";"crypto/sha256";"errors";"io";"os";"path/filepath";"strings";"sync";"testing")\n' + helper + test)
            env = dict(os.environ, GOMAXPROCS="2", GOWORK="off", GOFLAGS="")
            compiler = shutil.which("go")
            host_os, host_arch = subprocess.check_output([compiler, "env", "GOHOSTOS", "GOHOSTARCH"], env=env, text=True, timeout=15).split()
            race = [] if (host_os, host_arch) == ("windows", "arm64") else ["-race"]
            env.update(GOOS=host_os, GOARCH=host_arch, CGO_ENABLED="1" if race else "0")
            binary = path / ("provider-image.test.exe" if host_os == "windows" else "provider-image.test")
            print("Provider image phase=compile", flush=True)
            subprocess.run([compiler, "test", "-c", *race, "-p=1", "-o", str(binary), "."],
                           cwd=path, env=env, check=True, timeout=180)
            print("Provider image phase=execute", flush=True)
            result = subprocess.run([str(binary), "-test.run=^TestProviderImage$", "-test.count=1", "-test.timeout=15s", "-test.v"],
                                    cwd=path, env=env, capture_output=True, text=True, timeout=60)
            output = result.stdout + result.stderr
            print(output, end="" if output.endswith("\n") else "\n", flush=True)
            required = ["TestProviderImage", *("TestProviderImage/" + leaf for leaf in (
                "captured-independent-images", "bounded-write-and-retained-close", "failed-copy-never-adopts"))]
            if result.returncode or any(len(re.findall(r"(?m)^[ \t]*--- PASS: " + re.escape(case) + r" \(", output)) != 1 for case in required) or re.search(r"--- FAIL:|--- SKIP:|DATA RACE|panic:|fatal error:|\[build failed\]", output):
                raise AssertionError("Provider image copy omitted its independent immutable-source contract")


if __name__ == "__main__":
    unittest.main()
