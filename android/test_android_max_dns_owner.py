#!/usr/bin/env python3
"""Execute the shipping MAX DNS owner with only Android resolver handles doubled.

The barriers hold real app callbacks/workers after Cancel to prove that cleanup
does not return early. No public DNS query or VPN is started by this fixture.
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / 'android/app/src/main/java/com/eabusham/routervpn'

STUBS = {
    'android/content/Context.java': '''package android.content;
public class Context {public static final String CONNECTIVITY_SERVICE="connectivity"; public final android.net.ConnectivityManager connectivity=new android.net.ConnectivityManager();public Object getSystemService(String service){return connectivity;}public Context getApplicationContext(){return this;}}
''',
    'android/os/Build.java': '''package android.os;public final class Build {public static final class VERSION {public static int SDK_INT=35;}}''',
    'android/os/CancellationSignal.java': r'''package android.os;
public final class CancellationSignal {public interface OnCancelListener{void onCancel();}private boolean cancelled;private OnCancelListener listener;
 public void cancel(){OnCancelListener owned;synchronized(this){if(cancelled)return;cancelled=true;owned=listener;}if(owned!=null)owned.onCancel();}
 public void setOnCancelListener(OnCancelListener value){boolean notify;synchronized(this){listener=value;notify=cancelled;}if(notify&&value!=null)value.onCancel();}
 public synchronized boolean isCanceled(){return cancelled;}}
''',
    'android/net/NetworkCapabilities.java': '''package android.net;
public final class NetworkCapabilities {public static final int NET_CAPABILITY_INTERNET=12,TRANSPORT_VPN=4,TRANSPORT_WIFI=1,TRANSPORT_CELLULAR=0,TRANSPORT_ETHERNET=3;public boolean vpn,internet=true;public int transport=TRANSPORT_WIFI;public boolean hasTransport(int value){return value==TRANSPORT_VPN?vpn:value==transport;}public boolean hasCapability(int value){return internet&&value==NET_CAPABILITY_INTERNET;}}
''',
    'android/net/LinkProperties.java': '''package android.net;
public final class LinkProperties {public String name="wlan0",privateName;public boolean privateActive;public java.util.List<java.net.InetAddress> dns;public java.util.List<String> addresses=new java.util.ArrayList<>(java.util.List.of("192.0.2.2/24")),routes=new java.util.ArrayList<>(java.util.List.of("0.0.0.0/0 wlan0"));public LinkProperties(){try{dns=new java.util.ArrayList<>(java.util.List.of(java.net.InetAddress.getByAddress(new byte[]{(byte)192,0,2,53})));}catch(Exception e){throw new AssertionError(e);}}public java.util.List<java.net.InetAddress> getDnsServers(){return dns;}public String getInterfaceName(){return name;}public java.util.List<String> getLinkAddresses(){return addresses;}public java.util.List<String> getRoutes(){return routes;}public boolean isPrivateDnsActive(){return privateActive;}public String getPrivateDnsServerName(){return privateName;}}
''',
    'android/net/Network.java': r'''package android.net;
import java.net.*;import java.util.concurrent.*;
public class Network {public final long id;public final LinkProperties links=new LinkProperties();public final NetworkCapabilities caps=new NetworkCapabilities();public volatile int legacyCalls;public CountDownLatch legacyEntered,legacyRelease;public InetAddress[] answer;public Network(long id){this.id=id;try{answer=new InetAddress[]{InetAddress.getByAddress(new byte[]{(byte)198,51,100,17})};}catch(Exception e){throw new AssertionError(e);}}public long getNetworkHandle(){return id;}public InetAddress[] getAllByName(String hostname){legacyCalls++;if(legacyEntered!=null)legacyEntered.countDown();if(legacyRelease!=null)hold(legacyRelease);return answer;}static void hold(CountDownLatch latch){boolean interrupted=false;while(true){try{latch.await();break;}catch(InterruptedException e){interrupted=true;}}if(interrupted)Thread.currentThread().interrupt();}}
''',
    'android/net/ConnectivityManager.java': '''package android.net;
public class ConnectivityManager {public Network active=new Network(101);public Network[] networks={active};public Network getActiveNetwork(){return active;}public Network[] getAllNetworks(){return networks;}public NetworkCapabilities getNetworkCapabilities(Network n){for(Network value:networks)if(value==n)return value.caps;return null;}public LinkProperties getLinkProperties(Network n){for(Network value:networks)if(value==n)return value.links;return null;}}
''',
    'android/net/DnsResolver.java': r'''package android.net;
import android.os.*;import java.net.*;import java.util.*;import java.util.concurrent.*;import java.util.concurrent.atomic.*;
public final class DnsResolver {public static final int FLAG_NO_CACHE_LOOKUP=4;public static final DnsResolver INSTANCE=new DnsResolver();public static State next;public interface Callback<T>{void onAnswer(T result,int rcode);void onError(DnsException error);}public static class DnsException extends Exception{}
 public static final class State {public Network network;public String hostname;public int flags;public Executor executor;public Callback<? super List<InetAddress>> callback;public CancellationSignal signal;public CountDownLatch entered=new CountDownLatch(1),registrationRelease,cancelEntered,cancelRelease,callbackEntered,callbackRelease;public final AtomicInteger cancels=new AtomicInteger(),deliveries=new AtomicInteger();public boolean autoAnswer=true;public volatile boolean returned;
  public void answer(){executor.execute(()->{if(callbackEntered!=null)callbackEntered.countDown();if(callbackRelease!=null)Network.hold(callbackRelease);deliveries.incrementAndGet();callback.onAnswer(Arrays.asList(network.answer),0);});}}
 public static DnsResolver getInstance(){return INSTANCE;}
 public void query(Network n,String host,int flags,Executor executor,CancellationSignal signal,Callback<? super List<InetAddress>> callback){if(n==null)throw new AssertionError("ambient/default resolver used");State s=next;if(s==null)throw new AssertionError("unowned query");s.network=n;s.hostname=host;s.flags=flags;s.executor=executor;s.callback=callback;s.signal=signal;s.entered.countDown();if(s.registrationRelease!=null)Network.hold(s.registrationRelease);signal.setOnCancelListener(()->{if(s.cancelEntered!=null)s.cancelEntered.countDown();if(s.cancelRelease!=null)Network.hold(s.cancelRelease);s.cancels.incrementAndGet();});if(s.autoAnswer&&!signal.isCanceled())s.answer();s.returned=true;}}
''',
    'io/nekohasekai/libbox/RouterMAXEndpointResolver.java': '''package io.nekohasekai.libbox;public interface RouterMAXEndpointResolver {String ownerID();boolean current();String lookup(String hostname)throws Exception;void cancel();}''',
}

HARNESS = r'''package com.eabusham.routervpn;
import android.content.*;import android.net.*;import android.os.*;import org.json.*;import java.util.*;import java.util.concurrent.*;import java.util.concurrent.atomic.*;
public final class MAXDNSHarness {
 static int checks;static void check(boolean condition,String message){checks++;if(!condition)throw new AssertionError(message);}
 interface Attempt{void run()throws Exception;}static void reject(Attempt attempt)throws Exception{boolean failed=false;try{attempt.run();}catch(Exception expected){failed=true;}check(failed,"invalid captured DNS was adopted");}
 static void waitFor(CountDownLatch latch)throws Exception{check(latch.await(2,TimeUnit.SECONDS),"held boundary was not reached");}
 static final class Job {final AtomicReference<Throwable> error=new AtomicReference<>();final AtomicReference<String> result=new AtomicReference<>();final Thread thread;
  Job(Attempt run){thread=new Thread(()->{try{run.run();}catch(Throwable failed){error.set(failed);}},"fixture-worker");thread.start();}
  void done(boolean failed)throws Exception{thread.join(2000);check(!thread.isAlive(),"MAX worker was not joined");check((error.get()!=null)==failed,"MAX query adopted cancelled/invalid completion");}}
 static AndroidMAXDNSOwner owner(Context context)throws Exception{return new AndroidMAXDNSOwner(new AndroidMAXDNSOwner.Physical(context),()->true,"node.example");}
 static void success()throws Exception{
  for(int sdk:new int[]{24,28,29,35})for(String privacy:new String[]{"plain","opportunistic","strict"}){
   Build.VERSION.SDK_INT=sdk;Context c=new Context();c.connectivity.active.links.privateActive=!privacy.equals("plain");c.connectivity.active.links.privateName=privacy.equals("strict")?"private-dns.example":null;
   DnsResolver.State state=new DnsResolver.State();DnsResolver.next=state;AndroidMAXDNSOwner captured=owner(c);String before=captured.physical.snapshot;
   JSONObject result=new JSONObject(captured.lookup("node.example"));check(result.getString("owner_id").equals(captured.ownerID()),"DNS owner identity changed");check(result.getString("hostname").equals("node.example"),"DNS query hostname changed");check(result.getJSONArray("addresses").getString(0).equals("198.51.100.17"),"nonliteral/foreign DNS answer");check(captured.current(),"successful query retired its profile before native adoption");
   if(sdk>=29){check(state.network==c.connectivity.active&&state.hostname.equals("node.example")&&state.flags==DnsResolver.FLAG_NO_CACHE_LOOKUP,"query lost captured Network or uncached scope");check(state.cancels.get()==1,"app query descriptor was not retired");check(c.connectivity.active.legacyCalls==0,"modern query used a legacy/global lookup");}
   else check(c.connectivity.active.legacyCalls==1,"legacy lookup did not use captured Network receiver");
   if(sdk>=28){check(before.contains("private_dns_active"),"Private DNS policy missing from snapshot");check(before.contains(privacy.equals("strict")?"private-dns.example":"private_dns_name"),"opportunistic policy invented a hostname");}
   reject(()->captured.lookup("node.example"));captured.close();check(!captured.current(),"retired owner stayed current");
  }
 }
 static void exactHostname()throws Exception{
  Build.VERSION.SDK_INT=35;Context c=new Context();DnsResolver.State state=new DnsResolver.State();DnsResolver.next=state;
  AndroidMAXDNSOwner captured=new AndroidMAXDNSOwner(new AndroidMAXDNSOwner.Physical(c),()->true,"Captured-MAX.example.");
  reject(()->captured.lookup("captured-max.example"));check(state.network==null,"foreign hostname reached the captured resolver");
  JSONObject value=new JSONObject(captured.lookup("Captured-MAX.example."));check(value.getString("hostname").equals("Captured-MAX.example.")&&state.hostname.equals("Captured-MAX.example."),"valid native hostname was normalized or rejected");captured.close();
 }
 static void modernCancellation()throws Exception{
  Build.VERSION.SDK_INT=35;
  for(String boundary:new String[]{"registration","cancel","callback"}){
   Context c=new Context();DnsResolver.State state=new DnsResolver.State();state.autoAnswer=boundary.equals("callback");
   if(boundary.equals("registration"))state.registrationRelease=new CountDownLatch(1);
   if(boundary.equals("cancel")){state.cancelEntered=new CountDownLatch(1);state.cancelRelease=new CountDownLatch(1);}
   if(boundary.equals("callback")){state.callbackEntered=new CountDownLatch(1);state.callbackRelease=new CountDownLatch(1);}
   DnsResolver.next=state;AndroidMAXDNSOwner captured=owner(c);Job lookup=new Job(()->captured.lookup("node.example"));waitFor(state.entered);if(state.callbackEntered!=null)waitFor(state.callbackEntered);
   long before=System.nanoTime();captured.cancel();check(System.nanoTime()-before<250_000_000L,"Cancel waited for a foreign resolver callback");
   Job drain=new Job(captured::close);if(state.cancelEntered!=null)waitFor(state.cancelEntered);
   Thread.sleep(60);check(drain.thread.isAlive()&&lookup.thread.isAlive(),"DNS close returned before admitted callback/registration joined: "+boundary);
   if(state.registrationRelease!=null)state.registrationRelease.countDown();if(state.cancelRelease!=null)state.cancelRelease.countDown();if(state.callbackRelease!=null)state.callbackRelease.countDown();
   lookup.done(true);drain.done(false);check(!captured.current()&&state.cancels.get()==1,"cancelled query remained reusable");
   int delivered=state.deliveries.get();state.answer();Thread.sleep(20);check(delivered==state.deliveries.get(),"late executor task reached the retired query");
   // A late result on the former owner cannot adopt or cancel the next owner.
   DnsResolver.State next=new DnsResolver.State();DnsResolver.next=next;AndroidMAXDNSOwner replacement=owner(c);check(!replacement.ownerID().equals(captured.ownerID()),"resolver identity reused");replacement.lookup("node.example");captured.cancel();check(replacement.current(),"stale cancellation retired the replacement resolver");replacement.close();
  }
 }
 static void legacyCancellation()throws Exception{
  Build.VERSION.SDK_INT=24;Context c=new Context();Network network=c.connectivity.active;network.legacyEntered=new CountDownLatch(1);network.legacyRelease=new CountDownLatch(1);
  AndroidMAXDNSOwner captured=owner(c);Job lookup=new Job(()->captured.lookup("node.example"));waitFor(network.legacyEntered);
  long before=System.nanoTime();captured.cancel();check(System.nanoTime()-before<250_000_000L,"legacy Cancel blocked on getAllByName");Job drain=new Job(captured::close);
  Thread.sleep(60);check(lookup.thread.isAlive()&&drain.thread.isAlive(),"legacy resolver worker falsely claimed a completed drain");network.legacyRelease.countDown();lookup.done(true);drain.done(false);
 }
 static void changedPolicy()throws Exception{
  Build.VERSION.SDK_INT=35;
  for(String change:new String[]{"dns","private-name","private-active","interface","address","route","default","vpn","removed","source"}){
   Context c=new Context();AtomicBoolean source=new AtomicBoolean(true);DnsResolver.State state=new DnsResolver.State();state.autoAnswer=false;state.cancelEntered=new CountDownLatch(1);DnsResolver.next=state;
   AndroidMAXDNSOwner captured=new AndroidMAXDNSOwner(new AndroidMAXDNSOwner.Physical(c),source::get,"node.example");Job lookup=new Job(()->captured.lookup("node.example"));waitFor(state.entered);LinkProperties p=c.connectivity.active.links;
   switch(change){case "dns":p.dns=java.util.List.of(java.net.InetAddress.getByAddress(new byte[]{(byte)192,0,2,54}));break;case "private-name":p.privateName="different.example";break;case "private-active":p.privateActive=true;break;case "interface":p.name="rmnet0";break;case "address":p.addresses.add("192.0.2.3/24");break;case "route":p.routes.add("192.0.2.0/24 wlan0");break;case "default":Network replacement=new Network(102);c.connectivity.networks=new Network[]{c.connectivity.active,replacement};c.connectivity.active=replacement;break;case "vpn":c.connectivity.active.caps.vpn=true;break;case "removed":c.connectivity.networks=new Network[0];break;case "source":source.set(false);break;}
   waitFor(state.cancelEntered);lookup.done(true);captured.close();check(!captured.current(),"changed DNS/path policy stayed current: "+change);
  }
  Context absent=new Context();absent.connectivity.active.links.dns=java.util.List.of();reject(()->owner(absent));
  Context vpn=new Context();vpn.connectivity.active.caps.vpn=true;reject(()->owner(vpn));
  Context none=new Context();none.connectivity.active=null;reject(()->owner(none));
 }
 static void neverStarted()throws Exception{Build.VERSION.SDK_INT=35;Context c=new Context();AndroidMAXDNSOwner captured=owner(c);captured.cancel();captured.close();reject(()->captured.lookup("node.example"));}
 static void noOwnedThreads()throws Exception{for(int i=0;i<100;i++){boolean found=false;for(Thread thread:Thread.getAllStackTraces().keySet())if(thread.isAlive()&&thread.getName().startsWith("routervpn-max-dns-"))found=true;if(!found){check(true,"joined");return;}Thread.sleep(10);}throw new AssertionError("owned DNS thread escaped cleanup");}
 public static void main(String[] args)throws Exception{success();exactHostname();modernCancellation();legacyCancellation();changedPolicy();neverStarted();noOwnedThreads();System.out.println("Android MAX captured system DNS: PASS "+checks+" checks (physical Network/query handles doubled)");}
}
'''


def run_fixture(negative_controls=True):
    jar = Path(os.environ.get('ANDROID_JSON_JAR', '/usr/share/java/com.android.json.jar'))
    if not jar.is_file() or not shutil.which('javac'):
        raise RuntimeError('JDK and Android JSON implementation are required')
    with tempfile.TemporaryDirectory(prefix='routervpn-max-dns-owner-') as directory:
        folder = Path(directory)
        for name, text in STUBS.items():
            path = folder / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        path = folder / 'com/eabusham/routervpn/AndroidMAXDNSOwner.java'
        path.parent.mkdir(parents=True, exist_ok=True)
        original = (JAVA / path.name).read_text()
        path.write_text(original)
        (path.parent / 'MAXDNSHarness.java').write_text(HARNESS)
        classes = folder / 'classes'
        compile_args = ['javac', '--release', '17', '-encoding', 'UTF-8', '-proc:none', '-cp', str(jar), '-d', str(classes), *map(str, folder.rglob('*.java'))]
        run_args = ['java', '-cp', os.pathsep.join((str(classes), str(jar))), 'com.eabusham.routervpn.MAXDNSHarness']
        subprocess.run(compile_args, check=True, timeout=45)
        subprocess.run(run_args, check=True, timeout=20)
        if negative_controls:
            controls = [
                ('while (!callbacks.isTerminated()) {', 'while (false && !callbacks.isTerminated()) {', 'admitted callback join'),
                ('@Override public void join() { Thread owned = worker; if (owned != null) joinThread(owned); }', '@Override public void join() {}', 'legacy worker join'),
                ('!snapshot.equals(snapshot(connectivity))', 'false', 'captured DNS policy snapshot'),
            ]
            for old, new, label in controls:
                if original.count(old) != 1:
                    raise AssertionError(label + ' control source changed')
                path.write_text(original.replace(old, new))
                subprocess.run(compile_args, check=True, timeout=45)
                try:
                    result = subprocess.run(run_args, capture_output=True, text=True, timeout=12)
                except subprocess.TimeoutExpired as stuck:
                    output = (stuck.stderr or b'').decode() if isinstance(stuck.stderr, bytes) else (stuck.stderr or '')
                    if 'AssertionError' not in output:
                        raise AssertionError(label + ' stalled without reaching its intended assertion')
                else:
                    if result.returncode == 0 or 'AssertionError' not in result.stderr:
                        raise AssertionError(label + ' control escaped')
                path.write_text(original)
            print('Android MAX DNS controls: PASS (callback join, legacy worker join and policy snapshot mutations rejected)')


if __name__ == '__main__':
    run_fixture()
