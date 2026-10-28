#!/usr/bin/env python3
"""Run the whole single-node strategy owner against delayed native startup.

The actual orchestrator, profile selection, JSON and kill-switch policy compile
unchanged. The service boundary reports native UP after 21 real seconds. The
clock boundary forwards real nanoTime and can step wall time independently;
no production timer or native initial-key deadline is shortened for the test.
"""
from pathlib import Path
import importlib.util
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / "android/app/src/main/java/com/eabusham/routervpn"


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def replace_once(source, old, new):
    assert source.count(old) == 1, "Declared fixture seam changed: " + old
    return source.replace(old, new, 1)


CLOCK = r'''package com.eabusham.routervpn;
final class System {
 static final java.io.PrintStream out=java.lang.System.out;
 static volatile boolean jumpWall;
 private static int reads;
 static long nanoTime(){return java.lang.System.nanoTime();}
 static synchronized long currentTimeMillis(){return java.lang.System.currentTimeMillis()+(jumpWall&&++reads>1?60000L:0L);}
 static synchronized void reset(){jumpWall=false;reads=0;}
}
'''

HARNESS = r'''package com.eabusham.routervpn;
import org.json.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;

public final class ModeStartupHarness {
 static int checks;
 static final String[] KEYS={"wg-pq","awg2-pq","max-tls-wg","max-tls-awg","max-quic-wg","max-quic-awg"};
 static void check(boolean ok,String why){checks++;if(!ok)throw new AssertionError("STARTUP-CHECK: "+why);}
 static StrategyHarness.Owner owner(String mode)throws Exception{
  System.reset();return new StrategyHarness.Owner(StrategyHarness.source(mode.contains("awg")?"awg":"wg",false,true,mode));
 }
 static StrategyHarness.Result launch(StrategyHarness.Owner owner,String mode)throws Exception{
  StrategyHarness.Result result=new StrategyHarness.Result();
  owner.chooser.startup(owner.file,"last",mode,Files.readString(owner.file.toPath()),result);return result;
 }
 static void await(StrategyHarness.Owner owner,StrategyHarness.Result result,long seconds,String why)throws Exception{
  check(result.done.await(seconds,TimeUnit.SECONDS),why);
  long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(2);
  while(owner.chooser.isRunning()&&System.nanoTime()<end)Thread.yield();
  check(!owner.chooser.isRunning(),"finished startup kept its selection worker");
 }
 static void budgets()throws Exception{
  for(int i=0;i<StrategyHarness.catalog.length();i++){
   String mode=StrategyHarness.catalog.getJSONObject(i).getString("id");
   long expected=20000L+(Arrays.asList(KEYS).contains(mode)?NATIVE_KEY_BUDGET_MS:0L);
   check(AndroidModeOrchestrator.libboxStartupTimeoutMillis(mode)==expected,"captured raw mode budget differs: "+mode);
  }
  for(String mode:new String[]{"WG-PQ","wg-pq ","max","reality-pq-vision","unknown"})
   check(AndroidModeOrchestrator.libboxStartupTimeoutMillis(mode)==20000L,"ordinary/unknown mode inherited a native key phase: "+mode);
 }
 static void delayed()throws Exception{
  try(StrategyHarness.Owner owner=owner("wg-pq")){
   Step step=new Step("");step.readyAfterMillis=21100L;Env.plan("wg-pq",step);
   System.jumpWall=true;long start=System.nanoTime();StrategyHarness.Result result=launch(owner,"wg-pq");
   await(owner,result,35,"delayed native startup did not finish within its captured bound");
   long elapsed=TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-start);
   check(result.success&&result.mode.equals("wg-pq")&&elapsed>=21100L,"legitimate native initial key was clipped by the strategy deadline");
   check(Env.adoptions==1&&Env.mtuStarts==1&&result.receipts==1&&Env.events.contains("proof:wg-pq"),"delayed startup skipped fresh proof or captured adoption");
   check(AndroidHomeStateStore.current.connected&&Env.starts==1,"delayed startup borrowed a fallback path");
   System.jumpWall=false;
   StrategyHarness.Result stopped=new StrategyHarness.Result();owner.chooser.disconnectCaptured(result.owner,stopped);
   await(owner,stopped,4,"retained startup owner did not drain");
   check(stopped.success&&!owner.chooser.isActive(),"proved startup lost exact cleanup ownership");
   System.out.println("Single-node shipping strategy accepted native UP after "+elapsed+"ms with fresh proof, receipt and MTU adoption");
  }
 }
 static void ordinary()throws Exception{
  try(StrategyHarness.Owner owner=owner("shadowsocks")){
   Step step=new Step("");step.readyAfterMillis=60000L;Env.plan("shadowsocks",step);
   long start=System.nanoTime();StrategyHarness.Result result=launch(owner,"shadowsocks");
   await(owner,result,30,"ordinary startup exceeded its original deadline");
   long elapsed=TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-start);
   check(!result.success&&elapsed>=19500L&&elapsed<25000L,"ordinary startup budget changed");
   check(Env.adoptions==0&&Env.mtuStarts==0&&result.receipts==0&&!owner.chooser.isActive()&&!AndroidHomeStateStore.current.connected,"timed-out ordinary startup leaked a runtime or proof");
   check(Env.events.contains("stop:shadowsocks")&&!Env.events.contains("proof:shadowsocks"),"ordinary expiry did not stop before proof");
   System.out.println("Single-node ordinary startup expired and drained after "+elapsed+"ms");
  }
 }
 static void pending(String only)throws Exception{
  for(String mode:KEYS)for(String fault:new String[]{"cancel","generation","FAILED","REVOKED"}){
   if(!only.isEmpty()&&!fault.equals(only))continue;
   try(StrategyHarness.Owner owner=owner(mode)){
    CountDownLatch entered=new CountDownLatch(1);Step step=new Step("");step.readyAfterMillis=60000L;step.started=entered::countDown;Env.plan(mode,step);
    StrategyHarness.Result result=launch(owner,mode);check(entered.await(3,TimeUnit.SECONDS),"captured native startup was never reached");
    StrategyHarness.Result stop=null;long start=System.nanoTime();
    if(fault.equals("cancel")){stop=new StrategyHarness.Result();owner.chooser.disconnect(stop);}
    else if(fault.equals("generation"))AndroidHomeStateStore.advancePathGeneration(owner.context);
    else owner.sing.engine.state=fault;
    await(owner,result,4,"pending startup ignored its captured path generation or cancellation");
    if(stop!=null){await(owner,stop,4,"Disconnect did not join pending startup");check(stop.success,"Disconnect lost captured startup cleanup");}
    check(!result.success&&TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-start)<3000L,"expanded startup waited through a canceled or terminal owner");
    check(Env.adoptions==0&&Env.mtuStarts==0&&result.receipts==0&&!owner.chooser.isActive()&&!AndroidHomeStateStore.current.connected,"invalid native startup was adopted");
    check(!Env.events.contains("proof:"+mode),"retired startup reached a private-node proof");
   }
  }
 }
 public static void main(String[] args)throws Exception{
  StrategyHarness.directory=Path.of(args[0]);StrategyHarness.catalog=new JSONArray(Files.readString(Path.of(args[1])));StrategyHarness.logical=new JSONArray(Files.readString(Path.of(args[2])));
  switch(args[3]){case"delayed":delayed();break;case"generation":pending("generation");break;default:budgets();pending("");delayed();ordinary();}
  System.out.println("Single-node captured startup: "+checks+" executable checks PASS");
 }
}
'''


def main():
    fixtures = module("strategy_startup_sources", ROOT / "android/test_android_mode_orchestrator.py")
    dependency = module("strategy_startup_json", ROOT / "deploy/test_android_multihop_pinned.py")
    key = re.search(r"(?m)^const InitialKeyTimeout\s*=\s*(\d+)\s*\*\s*time.Second\s*$",
                    (ROOT / "internal/mobilepq/controller.go").read_text())
    assert key, "Actual native initial-key contract changed"
    harness = HARNESS.replace("NATIVE_KEY_BUDGET_MS", str(int(key[1]) * 1000) + "L")
    sources = dict(fixtures.SOURCES)
    boundary = sources["com/eabusham/routervpn/StrategyBoundaries.java"]
    boundary = replace_once(boundary, "final String fault; boolean proof=true, failStop; Runnable prepared, proved;",
                            "final String fault; boolean proof=true, failStop; Runnable prepared, proved, started; long readyAfterMillis;")
    boundary = replace_once(boundary, 'final String kind; String state="DOWN",mode=""; Step step;',
                            'final String kind; volatile String state="DOWN"; String mode=""; Step step; long startedAt;')
    boundary = replace_once(boundary, 'mode=id;step=next;Env.current=this;state="UP";Env.events.add("start:"+id);Env.starts++;',
                            'mode=id;step=next;Env.current=this;startedAt=java.lang.System.nanoTime();state=next.readyAfterMillis>0?"STARTING":"UP";Env.events.add("start:"+id);Env.starts++;if(next.started!=null)next.started.run();')
    boundary = replace_once(boundary, " void stop(){\n", ''' String readState(){if("STARTING".equals(state)&&java.lang.System.nanoTime()-startedAt>=java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(step.readyAfterMillis))state="UP";return state;}
 void stop(){
''')
    boundary = boundary.replace("String getState(){return engine.state;}", "String getState(){return engine.readState();}")
    sources["com/eabusham/routervpn/StrategyBoundaries.java"] = boundary
    sources["com/eabusham/routervpn/System.java"] = CLOCK
    sources["com/eabusham/routervpn/ModeStartupHarness.java"] = harness
    original = (JAVA / "AndroidModeOrchestrator.java").read_text()
    with tempfile.TemporaryDirectory(prefix="routervpn-single-node-startup-") as temporary:
        root = Path(temporary)
        jar = dependency.android_json_dependency(root, dict(os.environ))
        for name, source in sources.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source)
        for name in ("AndroidModeOrchestrator", "AndroidProfileSelection", "AndroidKillSwitchPolicy"):
            (root / "com/eabusham/routervpn" / (name + ".java")).write_bytes((JAVA / (name + ".java")).read_bytes())
        source = root / "com/eabusham/routervpn/AndroidModeOrchestrator.java"
        compile_command = ["javac", "--release", "17", "-Xlint:all,-auxiliaryclass", "-Werror", "-cp", str(jar), "-d", str(root), *map(str, root.rglob("*.java"))]
        command = ["java", "-cp", os.pathsep.join((str(root), str(jar))), "com.eabusham.routervpn.ModeStartupHarness", str(root), str(ROOT / "configs/client/modes.json"), str(ROOT / "configs/client/logical-modes.json")]
        subprocess.run(compile_command, check=True, timeout=45)
        subprocess.run(command + ["shipping"], check=True, timeout=75)
        variants = {
            "premature-budget": (replace_once(original, "TimeUnit.MILLISECONDS.toNanos(libboxStartupTimeoutMillis(id))", "TimeUnit.MILLISECONDS.toNanos(20_000L)"), "delayed", "legitimate native initial key was clipped"),
            "wall-clock": (original.replace("final long started=System.nanoTime();", "final long started=TimeUnit.MILLISECONDS.toNanos(System.currentTimeMillis());").replace("while(System.nanoTime()-started<timeout)", "while(TimeUnit.MILLISECONDS.toNanos(System.currentTimeMillis())-started<timeout)"), "delayed", "legitimate native initial key was clipped"),
            "missing-owner": (replace_once(original, "            checkSelection();\n            String state=sing.getState();", "            String state=sing.getState();"), "generation", "pending startup ignored its captured path generation"),
        }
        for name, (broken, case, expected) in variants.items():
            assert broken != original, name
            source.write_text(broken)
            subprocess.run(compile_command, check=True, timeout=45)
            result = subprocess.run(command + [case], text=True, capture_output=True, timeout=45)
            assert result.returncode != 0 and "STARTUP-CHECK: " + expected in result.stdout + result.stderr, name + ": " + result.stdout + result.stderr
            print("Single-node startup control " + name + ": rejected", flush=True)


if __name__ == "__main__":
    main()
