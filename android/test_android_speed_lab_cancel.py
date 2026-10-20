#!/usr/bin/env python3
"""Exercise actual Speed Lab cancellation while native HTTP I/O closes late."""
from pathlib import Path
import importlib.util
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / "android/app/src/main/java/com/eabusham/routervpn"
spec = importlib.util.spec_from_file_location("speed_cancel_boundaries", ROOT / "android/test_android_speed_lab_http_cleanup.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
STATE = H.STATE.replace("return new Snapshot();", "return current;").replace("static Snapshot snapshot", '''static volatile Snapshot current=initial();
    static Snapshot initial(){Snapshot value=new Snapshot();value.phase="off";value.pathProof="not-run";value.sessionId="";value.pathGeneration=1;return value;}
    static Snapshot snapshot''')
HARNESS = r'''package com.eabusham.routervpn;
import android.content.*;import java.io.*;import java.net.*;import java.util.*;import java.util.concurrent.*;import java.util.concurrent.atomic.*;
public final class SpeedLabCancelTest {
 static int checks;static volatile Scenario active;
 static void check(boolean ok,String why){checks++;if(!ok)throw new AssertionError(why);}
 static void await(CountDownLatch signal,String why)throws Exception{check(signal.await(3,TimeUnit.SECONDS),why);}
 static void uninterruptibly(CountDownLatch signal){boolean interrupted=false;while(true)try{signal.await();break;}catch(InterruptedException e){interrupted=true;}if(interrupted)Thread.currentThread().interrupt();}
 static final class Scenario {
  final String stage;final boolean failClose;final CountDownLatch entered=new CountDownLatch(1),opened=new CountDownLatch(1),openRelease=new CountDownLatch(1),closeEntered=new CountDownLatch(1),closeRelease=new CountDownLatch(1),ioRelease=new CountDownLatch(1);
  final List<Connection> values=Collections.synchronizedList(new ArrayList<>());final AtomicInteger pendingIO=new AtomicInteger(),pendingClose=new AtomicInteger(),headers=new AtomicInteger();volatile boolean selected,normalClose;
  Scenario(String stage,boolean failClose){this.stage=stage;this.failClose=failClose;}
  synchronized boolean choose(URL url){
   String thread=Thread.currentThread().getName();boolean match=stage.equals("open")||stage.equals("idle")?thread.equals("routervpn-speed-lab"):stage.equals("loaded")?thread.contains("loaded-"):stage.equals("download")?thread.contains("download-stream"):thread.contains("upload-stream");
   if(!selected&&match){selected=true;return true;}return false;
  }
 }
 static final class Connection extends HttpURLConnection {
  final Scenario scenario;final boolean blocking;final AtomicInteger closes=new AtomicInteger();volatile boolean finalClosed;
  Connection(URL url,Scenario scenario){super(url);this.scenario=scenario;blocking=scenario.choose(url);scenario.values.add(this);}
  public void connect(){}public boolean usingProxy(){return false;}
  public void disconnect(){
   int count=closes.incrementAndGet();
   if(blocking&&(Thread.currentThread().getName().equals("routervpn-speed-lab-http-close")||scenario.normalClose)){
    if(scenario.failClose&&count==1)throw new IllegalStateException("native close must be retried");
    scenario.pendingClose.incrementAndGet();scenario.closeEntered.countDown();uninterruptibly(scenario.closeRelease);scenario.pendingClose.decrementAndGet();scenario.ioRelease.countDown();
   }
   finalClosed=true;
  }
  public int getResponseCode()throws IOException{
   scenario.headers.incrementAndGet();
   if(blocking&&!scenario.stage.equals("open")){scenario.pendingIO.incrementAndGet();scenario.entered.countDown();uninterruptibly(scenario.ioRelease);scenario.pendingIO.decrementAndGet();throw new IOException("cancelled captured HTTP request");}
   return 200;
  }
  public InputStream getInputStream(){
   long count=2;String query=getURL().getQuery();if(query!=null)for(String field:query.split("&"))if(field.startsWith("bytes="))count=Long.parseLong(field.substring(6));final long expected=count;
   return new InputStream(){long remaining=expected;public int read(){if(remaining--<=0)return -1;return 1;}public int read(byte[] bytes,int offset,int length){if(remaining<=0)return -1;int n=(int)Math.min(remaining,length);remaining-=n;return n;}};
  }
  public OutputStream getOutputStream(){return new OutputStream(){public void write(int value){}public void write(byte[] values,int offset,int length){}};}
 }
 static final class Result implements AndroidSpeedLab.Callback {
  final CountDownLatch done=new CountDownLatch(1);volatile Throwable error;volatile AndroidSpeedLab.Result result;int completions;
  public void finished(AndroidSpeedLab.Result value,Throwable failure){result=value;error=failure;completions++;done.countDown();}
 }
 static void cancel(String stage,boolean failClose)throws Exception{
  AndroidHomeStateStore.current=AndroidHomeStateStore.initial();Scenario scenario=new Scenario(stage,failClose);active=scenario;AndroidSpeedLab meter=new AndroidSpeedLab(new Context());Result result=new Result();meter.run("custom",1,1,result);
  if(stage.equals("open"))await(scenario.opened,"late URL factory was not reached");else await(scenario.entered,"captured "+stage+" I/O was not reached");
  long began=System.nanoTime();meter.cancel();check(System.nanoTime()-began<250_000_000L,"Cancel blocked on socket cleanup");
  if(stage.equals("open"))scenario.openRelease.countDown();await(scenario.closeEntered,"Cancel did not reach captured connection cleanup");
  Thread.sleep(100);check(result.done.getCount()==1&&meter.isRunning()&&scenario.pendingClose.get()>0,"measurement completed before late disconnect returned");
  Result duplicate=new Result();meter.run("custom",1,1,duplicate);await(duplicate.done,"duplicate request was not rejected");check(duplicate.error!=null&&result.completions==0,"duplicate measurement replaced draining request");
  scenario.closeRelease.countDown();await(result.done,"cancelled measurement did not complete after cleanup");
  check(result.error!=null&&result.result==null&&result.completions==1&&!meter.isRunning(),"cancelled throughput was published or owner stayed active");
  check(scenario.pendingIO.get()==0&&scenario.pendingClose.get()==0,"callback ran with outstanding HTTP I/O or cleanup");
  boolean closed=true,finalClose=true;for(Connection value:scenario.values){closed&=value.finalClosed;if(value.blocking)finalClose&=value.closes.get()>=2;}check(closed,"captured HTTP connection was not finally closed");check(finalClose,"early cancellation close replaced the final reader close");
  if(stage.equals("open"))check(scenario.headers.get()==0,"cancelled late connection factory opened network traffic");
  meter.cancel();check(result.completions==1,"late Cancel repeated completion");
 }
 static void stale()throws Exception{
  AndroidHomeStateStore.current=AndroidHomeStateStore.initial();Scenario scenario=new Scenario("idle",false);scenario.normalClose=true;active=scenario;AndroidSpeedLab meter=new AndroidSpeedLab(new Context());Result result=new Result();meter.run("custom",1,1,result);await(scenario.entered,"stale fixture did not enter HTTP");
  AndroidHomeStateStore.Snapshot newer=AndroidHomeStateStore.initial();newer.pathGeneration=2;AndroidHomeStateStore.current=newer;scenario.ioRelease.countDown();await(scenario.closeEntered,"stale read did not close its connection");Thread.sleep(80);check(result.completions==0&&meter.isRunning(),"stale measurement released path before close");scenario.closeRelease.countDown();await(result.done,"stale measurement failed to drain");check(result.error!=null&&result.result==null&&scenario.pendingClose.get()==0,"stale path was accepted");
 }
 public static void main(String[] args)throws Exception{
  try{
   URL.setURLStreamHandlerFactory(protocol->new URLStreamHandler(){protected URLConnection openConnection(URL url){throw new AssertionError("ambient proxy used");}protected URLConnection openConnection(URL url,Proxy proxy){if(!Proxy.NO_PROXY.equals(proxy)||!"speed.cloudflare.com".equals(url.getHost())||!"https".equals(protocol))throw new AssertionError("unowned provider");Scenario scenario=active;Connection value=new Connection(url,scenario);if(value.blocking&&scenario.stage.equals("open")){scenario.opened.countDown();uninterruptibly(scenario.openRelease);}return value;}});
   for(String stage:new String[]{"open","idle","download","loaded","upload"})cancel(stage,false);cancel("idle",true);stale();
   System.out.println("Android Speed Lab cancellation: "+checks+" checks; late connection creation, idle/load/transfer I/O, close retry, duplicate/stale rejection and final drain");
  }catch(Throwable error){error.printStackTrace();System.exit(1);}
 }
}'''


def main():
    if not shutil.which("javac"):
        raise RuntimeError("JDK required for real Speed Lab cancellation tests")
    with tempfile.TemporaryDirectory(prefix="routervpn-speed-cancel-") as directory:
        root = Path(directory)
        sources = {
            "android/content/Context.java": H.CONTEXT,
            "org/json/JSONObject.java": H.JSON,
            "com/eabusham/routervpn/AndroidHomeStateStore.java": STATE,
            "com/eabusham/routervpn/SpeedLabCancelTest.java": HARNESS,
            "com/eabusham/routervpn/AndroidSpeedLab.java": (JAVA / "AndroidSpeedLab.java").read_text(),
        }
        for name, content in sources.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        compile_args = ["javac", "--release", "17", "-encoding", "UTF-8", "-d", str(root / "classes"), *map(str, root.rglob("*.java"))]
        run_args = ["java", "-cp", str(root / "classes"), "com.eabusham.routervpn.SpeedLabCancelTest"]
        subprocess.run(compile_args, check=True, timeout=45)
        subprocess.run(run_args, check=True, timeout=35)
        path = root / "com/eabusham/routervpn/AndroidSpeedLab.java"
        original = path.read_text()
        for before, after, label in (
            ("if(work!=null)work.cancel();}", "}", "Cancel reaches native HTTP handles"),
            ("while(closing)try{wait();}", "while(closing&&false)try{wait();}", "final close joins the outstanding cancellation close"),
            ("owned.check();\n            c.setConnectTimeout(2500)", "c.setConnectTimeout(2500)", "cancelled late factory cannot open HTTP traffic"),
        ):
            if original.count(before) != 1:
                raise AssertionError("Missing unique boundary: " + label)
            path.write_text(original.replace(before, after))
            subprocess.run(compile_args, check=True, timeout=45)
            result = subprocess.run(run_args, capture_output=True, text=True, timeout=20)
            if result.returncode == 0 or "AssertionError" not in result.stderr:
                raise AssertionError("Negative control escaped: " + label + "\n" + result.stderr)
            path.write_text(original)
        print("Android Speed Lab cancellation negative controls: 3 rejected")


if __name__ == "__main__":
    main()
