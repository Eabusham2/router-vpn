#!/usr/bin/env python3
"""Execute shipping revalidation with native-proof and Home transaction doubles.

The production Java worker runs unchanged. There is no network request; these
checks exercise proof adoption and stale cleanup, not device networking.
"""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / "android/app/src/main/java/com/eabusham/routervpn"

BOUNDARIES = r'''package com.eabusham.routervpn;
import android.content.Context;
import java.io.File;
import java.util.Arrays;
final class AndroidExternalPolicy {
    // PRODUCTION_EXTERNAL_PREDICATE
}
final class AndroidTorProfile {static boolean isTor(String p){return p.equals("tor")||p.equals("tor-bridge");}}
final class AndroidUnderlyingNetworkMonitor {AndroidUnderlyingNetworkMonitor(Context c){}void start(Runnable r){}}
final class AndroidPathProbe {static boolean prove(File f,int timeout){return true;}}
final class AndroidNodeStore {AndroidNodeStore(Context c){}File file(String id){return new File(id);}}
final class AndroidModeOrchestrator {interface Callback {void progress(String text);void finished(boolean ok,String mode,String text);}}
final class AndroidRuntimeRegistry {
 final Standard standardExit=new Standard();final Other multihop=new Other(),orchestrator=new Other();
 static class Standard {
  int externalReads,torReads,stops;boolean healthy=true,failStop;Runnable afterProof;
  AndroidHomeStateStore.Snapshot captured;
  String read(AndroidHomeStateStore.Snapshot owner){captured=owner;if(afterProof!=null)afterProof.run();if(!healthy)throw new IllegalStateException("captured native DNS/entry proof expired");return "8.8.4.4";}
  String capturedExternalExit(AndroidHomeStateStore.Snapshot owner){externalReads++;return read(owner);}
  String capturedTorExit(AndroidHomeStateStore.Snapshot owner){torReads++;return read(owner);}
  void failClosedForRevalidation(){stops++;if(failStop)throw new IllegalStateException("native drain pending");}
 }
 static class Other {void failClosedForRevalidation(){}void disconnect(AndroidModeOrchestrator.Callback c){c.finished(true,"","");}}
}
final class AndroidHomeStateStore {
 static class Snapshot {
  boolean connected=true;long pathGeneration=4;
  String sessionId="owned",phase="connected",pathProof="passed",actualBase="sing-box",logicalMode="external";
  String activeExternalProtocol="openvpn",expectedExternalIp="8.8.4.4",activeExitId="exit",activeNodeId="node";
  Snapshot copy(){Snapshot s=new Snapshot();s.connected=connected;s.pathGeneration=pathGeneration;s.sessionId=sessionId;s.phase=phase;s.pathProof=pathProof;s.actualBase=actualBase;s.logicalMode=logicalMode;s.activeExternalProtocol=activeExternalProtocol;s.expectedExternalIp=expectedExternalIp;return s;}
 }
 static Snapshot current=new Snapshot();static int begins,completes,saves,failures,preserved;static String savedIP="";
 static void reset(){current=new Snapshot();begins=0;completes=0;saves=0;failures=0;preserved=0;savedIP="";}
 static Snapshot snapshot(Context c){return current;}
 static Snapshot beginPathRevalidation(Context c,String reason){begins++;Snapshot before=current;current=before.copy();current.pathGeneration++;current.connected=false;current.phase="connecting";current.pathProof="pending";return before;}
 static boolean completePathRevalidation(Context c,Snapshot token){if(!current.sessionId.equals(token.sessionId)||current.pathGeneration!=token.pathGeneration+1)return false;completes++;current.connected=true;current.phase="connected";current.pathProof="passed";return true;}
 static void saveActualExit(Context c,String session,String ip){if(!current.sessionId.equals(session))throw new AssertionError("saved exit belongs to another session");saves++;savedIP=ip;}
 static void failed(Context c,String message){failures++;current.connected=false;current.phase="failed";current.pathProof="failed";}
 static void failedPreservingOwnership(Context c,String message){preserved++;failed(c,message);}
}
'''

HARNESS = r'''package com.eabusham.routervpn;
import java.lang.reflect.*;
public class ExternalRevalidationTest {
 static int checks;static void check(boolean ok,String message){checks++;if(!ok)throw new AssertionError(message);}
 static class Fixture {
  final AndroidRuntimeRegistry engines=new AndroidRuntimeRegistry();
  final AndroidSessionRevalidator worker=new AndroidSessionRevalidator(new android.content.Context(),engines);
  Fixture(){AndroidHomeStateStore.reset();}
  void run()throws Exception{Method m=AndroidSessionRevalidator.class.getDeclaredMethod("revalidate");m.setAccessible(true);try{m.invoke(worker);}catch(InvocationTargetException e){throw new AssertionError("worker escaped failure handling",e.getCause());}}
 }
 static void supported()throws Exception {
  for(String p:new String[]{"wireguard","socks5","http","https","shadowsocks","hysteria2","openvpn"})for(boolean healthy:new boolean[]{true,false}){
   Fixture f=new Fixture();AndroidHomeStateStore.current.activeExternalProtocol=p;f.engines.standardExit.healthy=healthy;f.run();
   check(f.engines.standardExit.externalReads==1&&f.engines.standardExit.torReads==0,"external protocol bypassed native policy proof: "+p);
   check(f.engines.standardExit.captured.sessionId.equals("owned")&&f.engines.standardExit.captured.pathGeneration==5,"proof did not use current captured session/generation");
   check(AndroidHomeStateStore.current.connected==healthy,"unproven external path kept Connected: "+p);
   check(AndroidHomeStateStore.completes==(healthy?1:0)&&AndroidHomeStateStore.saves==(healthy?1:0),"failed native DNS/entry proof received public-IP-only adoption");
   check(f.engines.standardExit.stops==(healthy?0:1),"expired native proof failed to close its runtime");
   if(healthy)check(AndroidHomeStateStore.savedIP.equals("8.8.4.4"),"saved unrelated exit IP");
  }
 }
 static void rejected()throws Exception {
  for(String reason:new String[]{"unsupported","missing-target","interrupted"}){
   Fixture f=new Fixture();if(reason.equals("unsupported"))AndroidHomeStateStore.current.activeExternalProtocol="unowned";
   if(reason.equals("missing-target"))AndroidHomeStateStore.current.expectedExternalIp="";
   if(reason.equals("interrupted"))Thread.currentThread().interrupt();try{f.run();}finally{Thread.interrupted();}
   check(!AndroidHomeStateStore.current.connected&&AndroidHomeStateStore.completes==0&&AndroidHomeStateStore.saves==0,"invalid captured owner adopted a fallback proof: "+reason);
   check(f.engines.standardExit.externalReads==0&&f.engines.standardExit.stops==1,"invalid owner escaped fail-closed teardown: "+reason);
  }
 }
 static void stale()throws Exception {
  for(String reason:new String[]{"replacement","generation","disconnect"})for(boolean returns:new boolean[]{true,false}){
   Fixture f=new Fixture();f.engines.standardExit.healthy=returns;
   f.engines.standardExit.afterProof=()->{AndroidHomeStateStore.Snapshot next=AndroidHomeStateStore.current.copy();
    if(reason.equals("replacement"))next.sessionId="replacement";
    if(reason.equals("generation"))next.pathGeneration++;
    if(reason.equals("disconnect")){next.phase="disconnecting";next.pathProof="invalidated";}
    AndroidHomeStateStore.current=next;};
   f.run();check(AndroidHomeStateStore.completes==0&&AndroidHomeStateStore.saves==0,"late proof completed a replacement path: "+reason);
   check(f.engines.standardExit.stops==0&&AndroidHomeStateStore.failures==0,"stale proof stopped or failed the new owner: "+reason);
   check(!AndroidHomeStateStore.current.connected,"late proof revived Connected: "+reason);
  }
 }
 static void retainedTeardown()throws Exception {
  Fixture f=new Fixture();f.engines.standardExit.healthy=false;f.engines.standardExit.failStop=true;f.run();
  check(AndroidHomeStateStore.preserved==1&&!AndroidHomeStateStore.current.connected,"unconfirmed native stop lost retained Home ownership");
  check(AndroidHomeStateStore.current.sessionId.equals("owned")&&f.engines.standardExit.stops==1,"cleanup stole or released another owner");
 }
 static void tor()throws Exception {
  for(String p:new String[]{"tor","tor-bridge"}){Fixture f=new Fixture();AndroidHomeStateStore.current.activeExternalProtocol=p;AndroidHomeStateStore.current.expectedExternalIp="";f.run();
   check(f.engines.standardExit.torReads==1&&f.engines.standardExit.externalReads==0,"Tor circuit substituted an ordinary fixed-IP proof");
   check(AndroidHomeStateStore.current.connected&&AndroidHomeStateStore.saves==1,"valid owned Tor circuit was rejected");}
 }
 public static void main(String[]args)throws Exception{if(args.length!=0&&args[0].equals("unproven")){Fixture f=new Fixture();f.engines.standardExit.healthy=false;f.run();check(!AndroidHomeStateStore.current.connected,"unproven path adopted");return;}if(args.length!=0&&args[0].equals("stale")){stale();return;}supported();rejected();stale();retainedTeardown();tor();System.out.println("Android external revalidation: "+checks+" executable checks passed");}
}
'''


def main():
    if not shutil.which("javac") or not shutil.which("java"):
        raise RuntimeError("A JDK is required for external revalidation tests")
    predicates = re.findall(r"(?ms)^    static boolean supports\(String protocol\) \{\n.*?^    \}", (JAVA / "AndroidExternalPolicy.java").read_text())
    assert len(predicates) == 1, "exact shipping external protocol predicate is required"
    with tempfile.TemporaryDirectory(prefix="routervpn-external-revalidation-") as directory:
        temp = Path(directory)
        app = temp / "com/eabusham/routervpn"
        app.mkdir(parents=True)
        context = temp / "android/content/Context.java"
        context.parent.mkdir(parents=True)
        context.write_text("package android.content; public class Context {public Context getApplicationContext(){return this;}}")
        (app / "Boundaries.java").write_text(BOUNDARIES.replace("    // PRODUCTION_EXTERNAL_PREDICATE", predicates[0]))
        (app / "ExternalRevalidationTest.java").write_text(HARNESS)
        target = app / "AndroidSessionRevalidator.java"
        source = (JAVA / target.name).read_text()
        target.write_text(source)
        compile_args = ["javac", "--release", "17", "-encoding", "UTF-8", "-proc:none", "-d", str(temp / "classes"), *map(str, temp.rglob("*.java"))]
        run_args = ["java", "-cp", str(temp / "classes"), "com.eabusham.routervpn.ExternalRevalidationTest"]
        subprocess.run(compile_args, check=True, timeout=30)
        subprocess.run(run_args, check=True, timeout=30)
        # These mutations must fail executable behavior, not source-marker scans.
        for old, new, selected in (
            ("observed=engines.standardExit.capturedExternalExit(current);", "observed=current.expectedExternalIp;", "unproven"),
            ("if(!isSameRevalidation(token))return;", "", "stale"),
        ):
            assert source.count(old) == 1, "missing exact native-proof regression boundary"
            target.write_text(source.replace(old, new))
            subprocess.run(compile_args, check=True, timeout=30, capture_output=True)
            failed = subprocess.run([*run_args, selected], timeout=10, capture_output=True, text=True)
            assert failed.returncode != 0 and "AssertionError" in failed.stderr, "external revalidation negative control passed"
        print("Android external revalidation: 2 behavioral negative controls rejected")


if __name__ == "__main__":
    main()
