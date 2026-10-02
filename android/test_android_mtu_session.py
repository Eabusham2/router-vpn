#!/usr/bin/env python3
"""Execute production MTU session ownership against OS/native-boundary doubles.

Uses the real Android org.json library. This is not real-device VPN routing or
APK compilation; the existing SDK/AAR lanes must pass separately.
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
ROOT = Path(__file__).resolve().parent
STUBS = {}
def stub(package,name,body,kind='class'):
    STUBS[package.replace('.','/')+'/'+name+'.java']='package '+package+';\npublic '+kind+' '+name+' '+body
stub('android.content','SharedPreferences','''{String getString(String key,String fallback);Editor edit();interface Editor {Editor putString(String key,String value);boolean commit();}}''','interface')
stub('android.content','Context','''{public static final int MODE_PRIVATE=0;public static final String CONNECTIVITY_SERVICE="connectivity";public Object service;public SharedPreferences preferences;public Object getSystemService(String name){return service;}public SharedPreferences getSharedPreferences(String name,int mode){return preferences;}}''')
stub('android.os','Build','{public static class VERSION{public static int SDK_INT=36;}public static class VERSION_CODES{public static final int R=30;}}')
stub('android.os','Process','{public static int myUid(){return 2000;}}')
stub('android.os','SystemClock','{public static long elapsedRealtime(){return System.nanoTime()/1000000;}}')
stub('android.os','ParcelFileDescriptor','''implements AutoCloseable{public static int borrowed,closed;private boolean done;public static ParcelFileDescriptor fromFd(int fd)throws java.io.IOException{if(fd<0)throw new java.io.IOException();borrowed++;return new ParcelFileDescriptor();}public java.io.FileDescriptor getFileDescriptor(){return new java.io.FileDescriptor();}public void close(){if(done)throw new AssertionError("duplicate close");done=true;closed++;}}''')
stub('android.net','NetworkCapabilities','''{public static final int TRANSPORT_VPN=1,TRANSPORT_WIFI=2,TRANSPORT_CELLULAR=3,TRANSPORT_ETHERNET=4;public boolean vpn;public int uid=2000;public int transport=TRANSPORT_WIFI;public boolean hasTransport(int t){return t==TRANSPORT_VPN?vpn:t==transport;}public int getOwnerUid(){return uid;}}''')
stub('android.net','LinkProperties','''{public String name="tun0";public java.util.List<String> addresses=new java.util.ArrayList<>();public String getInterfaceName(){return name;}public java.util.List<String> getLinkAddresses(){return addresses;}public java.util.List<String> getRoutes(){return java.util.List.of("route");}public java.util.List<String> getDnsServers(){return java.util.List.of("dns");}}''')
stub('android.net','Network','''{public long handle;public NetworkCapabilities caps=new NetworkCapabilities();public LinkProperties links=new LinkProperties();public int bindings;public boolean fail;public Runnable hook;public Network(long h){handle=h;}public long getNetworkHandle(){return handle;}public void bindSocket(java.io.FileDescriptor fd)throws java.io.IOException{if(fail)throw new java.io.IOException("injected bind failure");bindings++;if(hook!=null)hook.run();}}''')
stub('android.net','ConnectivityManager','''{public Network[] networks=new Network[0];public Network active;public Network[] getAllNetworks(){return networks;}public Network getActiveNetwork(){return active;}public NetworkCapabilities getNetworkCapabilities(Network n){return n.caps;}public LinkProperties getLinkProperties(Network n){return n.links;}}''')
P='io.nekohasekai.libbox'
stub(P,'CommandServer','{}')
stub(P,'RouterMTUState','''{private String session,path,iface;private int mtu;public void setSession(String s){session=s;}public String getSession(){return session;}public void setPath(String s){path=s;}public String getPath(){return path;}public void setInterface(String s){iface=s;}public String getInterface(){return iface;}public void setMTU(int n){mtu=n;}public int getMTU(){return mtu;}}''')
stub(P,'RouterMTUPlatform','''{RouterMTUState captureMTU();void beginMTUChange(RouterMTUState s)throws Exception;void endMTUChange()throws Exception;void bindMTUSocket(RouterMTUState s,long fd)throws Exception;String readMTUCache();boolean compareAndSwapMTUCache(String a,String b);void abortMTU(String reason);}''','interface')
stub(P,'RouterMTU',r'''{
 public interface Action { void run() throws Exception; }
 public int starts,cancels,closes,closeFailures;
 public volatile boolean active,invalid,restored;
 public String id="",override;public Action closeHook;
 public void start(String request,boolean force)throws Exception {
  if(active||invalid)throw new IllegalStateException();
  id=request;starts++;active=true;restored=false;
 }
 public boolean running(){return active;}
 public void cancel(String request){if(id.equals(request)){cancels++;active=false;restored=true;}}
 public void networkChanged(){invalid=true;active=false;}
 public void close()throws Exception {
  closes++;if(closeHook!=null)closeHook.run();
  if(closeFailures>0){closeFailures--;throw new IllegalStateException("injected drain failure");}
  active=false;invalid=true;
 }
 public String statusJSON(){
  if(override!=null)return override;
  boolean idle=id.isEmpty()&&!invalid;
  return "{\"request_id\":\""+id+"\",\"phase\":\""+(invalid?"invalidated":active?"measuring":idle?"idle":"restored")
   +"\",\"source\":\""+(idle?"configured-unmeasured":"restored-unmeasured")
   +"\",\"running\":"+active+",\"complete\":"+(!active)+",\"restored\":"+restored
   +",\"measured\":false,\"original_mtu\":"+(idle?0:1280)+",\"effective_mtu\":"+(invalid?0:1280)+"}";
 }
}''')
stub(P,'Libbox','''{
 public interface Hook { void run(RouterMTU value) throws Exception; }
 public static volatile RouterMTU latest;public static volatile Hook afterCreate;
 public static int created;
 public static RouterMTU newRouterMTU(CommandServer core,RouterMTUPlatform owner,String config,String profile)throws Exception {
  if(owner.captureMTU()==null)throw new IllegalStateException("no capture");
  created++;RouterMTU value=new RouterMTU();latest=value;
  Hook hook=afterCreate;if(hook!=null)hook.run(value);
  return value;
 }
}''')
HARNESS=r'''
package com.eabusham.routervpn;
import android.content.*;
import android.net.*;
import io.nekohasekai.libbox.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
public class Main {
 static int checks;
 interface Operation{void run()throws Exception;}
 static void check(boolean value,String text){checks++;if(!value)throw new AssertionError(text);}
 static void rejects(Operation action,String text)throws Exception{checks++;try{action.run();}catch(Exception expected){return;}throw new AssertionError(text);}
 static class Store implements SharedPreferences {
  String value="";boolean fail,corrupt;
  public String getString(String key,String fallback){if(corrupt)throw new IllegalStateException();return value;}
  public SharedPreferences.Editor edit(){return new SharedPreferences.Editor(){String next;public SharedPreferences.Editor putString(String k,String v){next=v;return this;}public boolean commit(){if(fail)return false;value=next;return true;}};}
 }
 static class Fixture {
  Context context=new Context();ConnectivityManager cm=new ConnectivityManager();
  Network physical=new Network(1),vpn=new Network(2);Store store=new Store();int mtu=1280;int aborts;
  AndroidMTUSession owner;
  Fixture()throws Exception{physical.links.name="wlan0";physical.links.addresses.add("192.0.2.2/24");vpn.caps.vpn=true;cm.networks=new Network[]{physical,vpn};cm.active=vpn;context.service=cm;context.preferences=store;owner=new AndroidMTUSession(context,o->aborts++,name->mtu);}
  RouterMTUState establish()throws Exception{owner.beforeOpen();owner.established(1280);owner.registered("tun0");return owner.captureMTU();}
 }

 static void await(CountDownLatch latch,String message)throws Exception {
  if(!latch.await(2,TimeUnit.SECONDS))throw new AssertionError(message);
 }
 static Thread worker(Operation operation,AtomicReference<Throwable> error) {
  Thread thread=new Thread(()->{try{operation.run();}catch(Throwable failure){error.compareAndSet(null,failure);}});
  thread.setDaemon(true);thread.start();return thread;
 }
 static void join(Thread thread,AtomicReference<Throwable> error)throws Exception {
  thread.join(3000);check(!thread.isAlive(),"native lifecycle deadlocked");
  if(error.get()!=null)throw new AssertionError("worker failed",error.get());
 }
 static void constructorShutdown()throws Exception {
  Fixture fixture=new Fixture();fixture.establish();
  CountDownLatch constructing=new CountDownLatch(1),release=new CountDownLatch(1),closing=new CountDownLatch(1);
  AtomicInteger finished=new AtomicInteger(),callbacks=new AtomicInteger();
  AtomicReference<Throwable> error=new AtomicReference<>();
  Libbox.afterCreate=nativeOwner->{
   // Native Close can await a platform callback on another thread. Holding the
   // session's platform monitor during Close would deadlock that callback.
   nativeOwner.closeHook=()->{
    Thread callback=worker(()->{fixture.owner.captureMTU();callbacks.incrementAndGet();},error);
    callback.join(1000);
    if(callback.isAlive())throw new IllegalStateException("Close held the platform callback monitor");
   };
   constructing.countDown();await(release,"constructor was not released");
  };
  Thread activating=worker(()->fixture.owner.activate(new CommandServer(),"{}","{}"),error);
  Thread stopping=null;
  try {
   await(constructing,"constructor was not reached");
   stopping=worker(()->{closing.countDown();fixture.owner.close();finished.incrementAndGet();},error);
   await(closing,"Stop was not reached");
   long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(1);
   while(fixture.owner.captureMTU()!=null&&System.nanoTime()<end)Thread.sleep(1);
   check(fixture.owner.captureMTU()==null,"Stop did not revoke platform callbacks immediately");
   stopping.join(80);
   check(finished.get()==0,"shutdown returned while the native constructor still owned the session");
  } finally {
   release.countDown();Libbox.afterCreate=null;
   activating.join(3000);if(stopping!=null)stopping.join(3000);
  }
  join(activating,error);join(stopping,error);
  RouterMTU nativeOwner=Libbox.latest;
  check(nativeOwner.starts==0&&nativeOwner.closes==1&&callbacks.get()==1,"stale constructor started a probe, leaked its owner, or deadlocked Close");
  fixture.owner.close();check(nativeOwner.closes==1,"successful teardown was not idempotent");
  rejects(fixture.owner::drainForMeasurement,"closed unstarted optimizer was accepted by Speed Lab");
 }
 static void failedDrainRetry()throws Exception {
  Fixture fixture=new Fixture();fixture.establish();
  fixture.owner.activate(new CommandServer(),"{}","{}");RouterMTU nativeOwner=Libbox.latest;
  nativeOwner.closeFailures=1;rejects(fixture.owner::close,"native drain error was swallowed");
  check(nativeOwner.closes==1&&fixture.owner.captureMTU()==null,"failed close did not revoke the session");
  rejects(()->fixture.owner.request("start",fixture.owner.identity,"a".repeat(32)),"failed close allowed a new probe");
  fixture.owner.close();check(nativeOwner.closes==2,"failed native owner was not retained for retry");
  fixture.owner.close();check(nativeOwner.closes==2,"successful retry did not release its owner");
 }
 static void staleConstructorDrainRetry()throws Exception {
  Fixture fixture=new Fixture();fixture.establish();
  Libbox.afterCreate=nativeOwner->{nativeOwner.closeFailures=1;fixture.owner.networkChanged();};
  try { fixture.owner.activate(new CommandServer(),"{}","{}"); } finally { Libbox.afterCreate=null; }
  RouterMTU nativeOwner=Libbox.latest;
  check(nativeOwner.starts==0&&nativeOwner.closes==1,"stale factory result was not retired before startup");
  fixture.owner.close();check(nativeOwner.closes==2,"failed stale constructor drain lost the only native owner");
 }
 static void verifiedHandoff()throws Exception {
  Fixture idle=new Fixture();idle.establish();Object lease=AndroidMTUMeasurementGate.acquire();
  try {
   idle.owner.activate(new CommandServer(),"{}","{}");RouterMTU nativeOwner=Libbox.latest;
   check(nativeOwner.starts==0,"automatic probes ignored Speed Lab's startup hold");
   idle.owner.drainForMeasurement();
   check(!nativeOwner.restored&&nativeOwner.starts==0,"idle handoff fabricated a measured or restored result");
   nativeOwner.override="x".repeat(32769);
   rejects(idle.owner::drainForMeasurement,"idle handoff skipped bounded status validation");
   nativeOwner.override="{\"running\":false,\"restored\":true,\"effective_mtu\":1420}";
   rejects(idle.owner::drainForMeasurement,"handoff accepted a result that disagrees with actual OS MTU");
   nativeOwner.override=null;idle.mtu=1400;
   rejects(idle.owner::drainForMeasurement,"idle optimizer hid a failed OS MTU readback");
   idle.mtu=1280;idle.owner.networkChanged();
   rejects(idle.owner::drainForMeasurement,"inactive stale optimizer was accepted by Speed Lab");
  } finally { AndroidMTUMeasurementGate.release(lease);idle.owner.close(); }
  Fixture fixed=new Fixture();fixed.establish();fixed.owner.activate(new CommandServer(),"{}","{\"mtu_policy\":\"manual\"}");
  fixed.owner.drainForMeasurement();fixed.mtu=1400;
  rejects(fixed.owner::drainForMeasurement,"no-optimizer handoff skipped current OS MTU verification");
  fixed.owner.close();rejects(fixed.owner::drainForMeasurement,"stopped fixed policy passed Speed Lab handoff");
 }
 public static void main(String[] args)throws Exception{
  constructorShutdown();failedDrainRetry();staleConstructorDrainRetry();verifiedHandoff();
  Fixture a=new Fixture();check(a.owner.captureMTU()==null,"missing interface invented");RouterMTUState first=a.establish();check(first!=null&&first.getMTU()==1280,"initial actual readback lost");
  rejects(a.owner::beforeOpen,"unowned reader replacement allowed");
  RouterMTUState wrong=new RouterMTUState();wrong.setSession("other");wrong.setPath(first.getPath());wrong.setInterface(first.getInterface());wrong.setMTU(1280);
  rejects(()->a.owner.beginMTUChange(wrong),"foreign session mutated TUN");
  a.owner.beginMTUChange(first);a.owner.beforeOpen();a.mtu=1420;a.owner.established(1420);a.owner.registered("tun0");a.owner.endMTUChange();RouterMTUState second=a.owner.captureMTU();
  check(second!=null&&second.getMTU()==1420&&second.getSession().equals(first.getSession())&&second.getPath().equals(first.getPath())&&!second.getInterface().equals(first.getInterface()),"reader replacement changed encrypted session or kept stale interface identity");
  rejects(()->a.owner.bindMTUSocket(first,11),"stale socket capture accepted");
  a.owner.bindMTUSocket(second,12);check(a.vpn.bindings==1&&android.os.ParcelFileDescriptor.borrowed==1&&android.os.ParcelFileDescriptor.closed==1,"socket not bound to exact VPN or duplicate leaked");
  rejects(()->a.owner.bindMTUSocket(second,-1),"invalid socket descriptor accepted");a.vpn.fail=true;
  rejects(()->a.owner.bindMTUSocket(second,13),"binding failure fell back to ambient network");check(android.os.ParcelFileDescriptor.closed==2,"failed binding leaked duplicate");a.vpn.fail=false;
  a.vpn.caps.uid=3000;check(a.owner.captureMTU()==null,"another UID VPN accepted");a.vpn.caps.uid=2000;
  a.mtu=1280;check(a.owner.captureMTU()==null,"configured MTU passed as system readback");a.mtu=1420;
  Network duplicate=new Network(3);duplicate.caps.vpn=true;a.cm.networks=new Network[]{a.physical,a.vpn,duplicate};check(a.owner.captureMTU()==null,"ambiguous TUN owner accepted");a.cm.networks=new Network[]{a.physical,a.vpn};
  a.vpn.hook=()->a.physical.links.addresses.add("198.51.100.2/24");rejects(()->a.owner.bindMTUSocket(second,15),"path change during bind accepted");check(a.owner.captureMTU()==null,"changed path not invalidated");rejects(a.owner::beforeOpen,"stale path restarted");
  Fixture b=new Fixture();RouterMTUState live=b.establish();b.owner.beginMTUChange(live);b.owner.close();rejects(b.owner::beforeOpen,"Stop undone by rollback");check(b.owner.captureMTU()==null,"stopped readback remained current");
  Fixture c=new Fixture();c.establish();check(c.owner.compareAndSwapMTUCache("","one"),"initial CAS rejected");check(!c.owner.compareAndSwapMTUCache("wrong","two")&&c.store.value.equals("one"),"CAS clobbered another writer");c.store.fail=true;check(!c.owner.compareAndSwapMTUCache("one","two")&&c.store.value.equals("one"),"failed persistence counted successful");c.store.corrupt=true;check(c.owner.readMTUCache().equals("invalid-cache"),"invalid private store silently accepted");
  Fixture d=new Fixture();d.establish();int before=Libbox.created;d.owner.activate(new CommandServer(),"{}","{\"mtu_policy\":\"auto\"}");RouterMTU nativeOwner=Libbox.latest;check(Libbox.created==before+1&&nativeOwner.starts==1,"Auto did not start once");d.owner.activate(new CommandServer(),"{}","{}");check(nativeOwner.starts==1,"duplicate automatic activation");
  rejects(()->d.owner.request("start","foreign","a".repeat(32)),"foreign UI generation accepted");
  Object lease=AndroidMTUMeasurementGate.acquire();d.owner.drainForMeasurement();check(!nativeOwner.running()&&nativeOwner.restored&&nativeOwner.cancels==1,"measurement did not cancel and drain Auto-MTU");rejects(()->d.owner.request("start",d.owner.identity,"b".repeat(32)),"Speed Lab allowed TUN mutation");AndroidMTUMeasurementGate.release(lease);
  d.owner.request("start",d.owner.identity,"c".repeat(32));check(nativeOwner.starts==2,"valid Retest not started");d.owner.request("cancel",d.owner.identity,"c".repeat(32));check(nativeOwner.cancels==2,"matching Cancel not delivered");
  nativeOwner.override="x".repeat(32769);rejects(()->d.owner.request("status","",""),"oversized IPC accepted");nativeOwner.override=null;
  d.physical.links.addresses.add("203.0.113.2/24");d.owner.checkNetwork();check(nativeOwner.invalid,"physical transition did not invalidate controller");d.owner.close();check(nativeOwner.closes==1,"native MTU not drained at teardown");
  Fixture e=new Fixture();e.establish();before=Libbox.created;e.owner.activate(new CommandServer(),"{}","{\"mtu_policy\":\"manual\"}");check(Libbox.created==before,"fixed policy entered Auto-MTU");
  Fixture f=new Fixture();f.establish();before=Libbox.created;f.owner.activate(new CommandServer(),"{}","{\"jumbo_tun\":true}");check(Libbox.created==before,"Jumbo entered Auto-MTU");
  System.out.println("Production Android MTU session: PASS ("+checks+" checks; OS VPN/native boundary doubled)");
 }
}
'''
def main():
    for command in ('javac','java'):
        if not shutil.which(command):raise RuntimeError('JDK required for actual MTU adapter tests')
    jar=Path(os.environ.get('ANDROID_JSON_JAR','/usr/share/java/com.android.json.jar'))
    if not jar.is_file():raise RuntimeError('Install libandroid-json-java or set ANDROID_JSON_JAR; do not skip this test')
    with tempfile.TemporaryDirectory(prefix='routervpn-mtu-session-') as directory:
        root=Path(directory)
        for name,source in STUBS.items():
            path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(source)
        app=root/'com/eabusham/routervpn';app.mkdir(parents=True,exist_ok=True);(app/'Main.java').write_text(HARNESS)
        for name in ['AndroidMTUSession.java','AndroidMTUMeasurementGate.java']:
            shutil.copyfile(ROOT/'app/src/main/java/com/eabusham/routervpn'/name,app/name)
        output=root/'classes';sources=[str(p) for p in root.rglob('*.java')]
        subprocess.run(['javac','--release','17','-encoding','UTF-8','-cp',str(jar),'-d',str(output),*sources],check=True,timeout=45)
        subprocess.run(['java','-cp',str(output)+os.pathsep+str(jar),'com.eabusham.routervpn.Main'],check=True,timeout=30)
if __name__=='__main__':main()
