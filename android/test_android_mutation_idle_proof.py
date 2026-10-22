#!/usr/bin/env python3
"""Run the actual mutation guard with deterministic engine/network boundary doubles."""
from pathlib import Path
import shutil,subprocess,tempfile
ROOT=Path(__file__).resolve().parents[1]
JAVA=ROOT/'android/app/src/main/java/com/eabusham/routervpn'
SOURCES={
'android/content/Context.java':'''package android.content; public class Context {public static final String CONNECTIVITY_SERVICE="connectivity"; public static Object service=new android.net.ConnectivityManager(); public static boolean denyLookup; public Object getSystemService(String key){if(denyLookup)throw new SecurityException("service denied");return service;}}''',
'android/net/ConnectivityManager.java':'''package android.net; public class ConnectivityManager {public static Network active; public static NetworkCapabilities caps=new NetworkCapabilities(); public static boolean denyActive,denyCapabilities; public Network getActiveNetwork(){if(denyActive)throw new SecurityException("network denied");return active;} public NetworkCapabilities getNetworkCapabilities(Network n){if(denyCapabilities)throw new SecurityException("capabilities denied");return caps;}}''',
'android/net/Network.java':'package android.net; public class Network {}',
'android/net/NetworkCapabilities.java':'''package android.net; public class NetworkCapabilities {public static final int TRANSPORT_VPN=4; public static boolean vpn,denyOwner; public static int owner=1000,ownerCalls; public boolean hasTransport(int t){return vpn;} public int getOwnerUid(){ownerCalls++;if(android.os.Build.VERSION.SDK_INT<30)throw new NoSuchMethodError("getOwnerUid requires API30");if(denyOwner)throw new SecurityException("owner denied");return owner;}}''',
'android/os/Build.java':'package android.os; public class Build {public static class VERSION {public static int SDK_INT=35;} public static class VERSION_CODES {public static final int Q=29,R=30;}}',
'android/os/Process.java':'package android.os; public class Process {public static int myUid(){return 1000;}}',
'com/wireguard/android/backend/Tunnel.java':'package com.wireguard.android.backend; public interface Tunnel {enum State {DOWN,UP}}',
'org/amnezia/awg/backend/Tunnel.java':'package org.amnezia.awg.backend; public interface Tunnel {enum State {DOWN,UP}}',
'com/eabusham/routervpn/GuardBoundaries.java':r'''package com.eabusham.routervpn;
import android.content.Context;
final class AndroidViaEntryLatencyProbe {static boolean active;static boolean hasActiveOperation(){return active;}}
final class AndroidHomeStateStore {
    static final class Snapshot {boolean connected;String phase="failed";}
    static Snapshot home=new Snapshot();static Snapshot snapshot(Context c){return home;}
}
final class AndroidRuntimeRegistry {
    static AndroidRuntimeRegistry current=new AndroidRuntimeRegistry();
    static AndroidRuntimeRegistry get(Context c){return current;}
    final Orchestrator orchestrator=new Orchestrator();
    final RuntimeState multihop=new RuntimeState(),standardExit=new RuntimeState();
    final WG wireGuard=new WG();final AWG amneziaWG=new AWG();
    final Embedded singBox=new Embedded(),xray=new Embedded();
    static final class Orchestrator {boolean running,active=true;boolean isRunning(){return running;}boolean isActive(){return active;}}
    static final class RuntimeState {boolean busy;boolean isActiveOrTransitioning(){return busy;}}
    static final class Embedded {String state="DOWN";String getState(){return state;}}
    static final class WG {com.wireguard.android.backend.Tunnel.State state=com.wireguard.android.backend.Tunnel.State.DOWN;com.wireguard.android.backend.Tunnel.State getState(){return state;}}
    static final class AWG {org.amnezia.awg.backend.Tunnel.State state=org.amnezia.awg.backend.Tunnel.State.DOWN;org.amnezia.awg.backend.Tunnel.State getState(){return state;}}
}
''',
'com/eabusham/routervpn/GuardHarness.java':r'''package com.eabusham.routervpn;
import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Build;
public final class GuardHarness {
    static int failed;static final Context context=new Context();
    static AndroidRuntimeRegistry reset(){
        Context.service=new ConnectivityManager();Context.denyLookup=false;
        ConnectivityManager.active=null;ConnectivityManager.caps=new NetworkCapabilities();
        ConnectivityManager.denyActive=false;ConnectivityManager.denyCapabilities=false;
        NetworkCapabilities.vpn=false;NetworkCapabilities.denyOwner=false;NetworkCapabilities.owner=1000;
        NetworkCapabilities.ownerCalls=0;
        Build.VERSION.SDK_INT=35;
        AndroidHomeStateStore.home=new AndroidHomeStateStore.Snapshot();
        AndroidViaEntryLatencyProbe.active=false;
        return AndroidRuntimeRegistry.current=new AndroidRuntimeRegistry();
    }
    static void check(String name,boolean expected){
        try {
            boolean actual=AndroidVpnMutationGuard.isBusy(context);
            if(actual!=expected){failed++;System.out.println("FAIL "+name+": busy="+actual);}
            else System.out.println("PASS "+name);
        } catch(Throwable error){failed++;System.out.println("FAIL "+name+": query escaped "+error);}
    }
    static void recovery(String name,boolean expected){
        try {
            boolean actual=AndroidVpnMutationGuard.failedSessionHasNoLiveEngine(context,AndroidRuntimeRegistry.current);
            if(actual!=expected){failed++;System.out.println("FAIL "+name+": recovery="+actual);}
            else System.out.println("PASS "+name);
        } catch(Throwable error){failed++;System.out.println("FAIL "+name+": query escaped "+error);}
    }
    public static void main(String[] args){
        AndroidRuntimeRegistry e=reset();check("completed failed session releases cached orchestrator marker",false);
        e=reset();AndroidViaEntryLatencyProbe.active=true;check("temporary entry reservation blocks mutation before native startup",true);
        e=reset();e.multihop.busy=true;check("failed Home cannot release unfinished multihop worker",true);
        e=reset();e.standardExit.busy=true;check("failed Home cannot release unfinished custom-exit worker",true);
        e=reset();e.multihop.busy=true;e.standardExit.busy=true;check("all remaining runtime owners must settle",true);
        e=reset();e.orchestrator.active=false;AndroidHomeStateStore.home.phase="off";e.wireGuard.state=null;check("unknown WireGuard state blocks mutation",true);
        e=reset();e.orchestrator.active=false;AndroidHomeStateStore.home.phase="off";e.amneziaWG.state=null;check("unknown AmneziaWG state blocks mutation",true);
        e=reset();e.singBox.state="STOPPING";check("pending Libbox stop acknowledgment blocks recovery",true);
        e=reset();e.xray.state="STOPPING";check("pending Xray stop acknowledgment blocks recovery",true);
        e=reset();e.orchestrator.active=false;AndroidHomeStateStore.home.phase="future-transition";check("unknown transition blocks mutation",true);
        e=reset();e.singBox.state=null;check("unknown embedded state blocks mutation",true);
        e=reset();AndroidHomeStateStore.home.connected=true;check("Connected Home never becomes idle",true);
        // Inspect real guard behavior when Android cannot return ownership proof.
        e=reset();Context.denyLookup=true;check("service exception keeps mutation locked",true);recovery("service exception cannot authorize recovery",false);
        e=reset();Context.service=null;check("missing service keeps mutation locked",true);recovery("missing service cannot authorize recovery",false);
        e=reset();ConnectivityManager.denyActive=true;check("active-network exception keeps mutation locked",true);recovery("active-network exception cannot authorize recovery",false);
        e=reset();ConnectivityManager.active=new Network();ConnectivityManager.caps=null;check("missing capabilities keep mutation locked",true);recovery("missing capabilities cannot authorize recovery",false);
        e=reset();ConnectivityManager.active=new Network();ConnectivityManager.denyCapabilities=true;check("capability exception keeps mutation locked",true);recovery("capability exception cannot authorize recovery",false);
        e=reset();ConnectivityManager.active=new Network();NetworkCapabilities.vpn=true;NetworkCapabilities.denyOwner=true;check("owner exception keeps mutation locked",true);recovery("owner exception cannot authorize recovery",false);
        e=reset();ConnectivityManager.active=new Network();check("known non-VPN network permits idle recovery",false);recovery("known non-VPN network confirms recovery",true);
        e=reset();ConnectivityManager.active=new Network();NetworkCapabilities.vpn=true;check("app-owned VPN blocks idle recovery",true);recovery("app-owned VPN still owns its session",false);
        e=reset();ConnectivityManager.active=new Network();NetworkCapabilities.vpn=true;NetworkCapabilities.owner=-1;check("unknown VPN owner blocks idle recovery",true);
        e=reset();ConnectivityManager.active=new Network();NetworkCapabilities.vpn=true;NetworkCapabilities.owner=2000;check("known foreign VPN is not our runtime",false);
        e=reset();Build.VERSION.SDK_INT=28;ConnectivityManager.active=new Network();NetworkCapabilities.vpn=true;NetworkCapabilities.owner=2000;check("older API cannot prove foreign ownership",true);
        e=reset();Build.VERSION.SDK_INT=29;ConnectivityManager.active=new Network();NetworkCapabilities.vpn=true;NetworkCapabilities.owner=2000;check("API29 cannot call API30 owner lookup or release an unknown VPN",true);
        if(NetworkCapabilities.ownerCalls!=0)throw new AssertionError("API29 mutation guard called API30 getOwnerUid");
        for(int sdk:new int[]{28,29,30,35})for(int owner:new int[]{-1,1000,2000}){
            reset();Build.VERSION.SDK_INT=sdk;NetworkCapabilities.owner=owner;NetworkCapabilities.vpn=true;Network current=new Network();ConnectivityManager.active=current;
            Network expected=sdk>=30&&owner==1000?current:null;
            if(HomeOwnership.inspect(context)!=expected||new ForwardOwnership(context).inspect()!=expected)throw new AssertionError("wrong Home/forwarding network owner on API"+sdk);
            if(sdk<30&&NetworkCapabilities.ownerCalls!=0)throw new AssertionError("old API called unavailable owner lookup");
        }
        System.out.println("PASS Home and forwarding API28/29/30/35 owner boundaries");
        if(failed>0)throw new AssertionError(failed+" mutation idle-proof regressions");
        System.out.println("Android actual mutation idle-proof behavior: PASS");
    }
}
'''
}
def shipping_method(name, signature):
    source=(JAVA/name).read_text()
    start=source.index('    '+signature)
    end=source.index('\n    private ',start+8)
    return source[start:end]

imports='package com.eabusham.routervpn;import android.content.Context;import android.net.*;import android.os.Build;import android.os.Process;'
SOURCES['com/eabusham/routervpn/HomeOwnership.java']=imports+'final class HomeOwnership {'+shipping_method('AndroidHomeSummary.java','private static Network ownedVpnNetwork(Context context)')+'static Network inspect(Context c){return ownedVpnNetwork(c);}}'
SOURCES['com/eabusham/routervpn/ForwardOwnership.java']=imports+'final class ForwardOwnership {final Context context;ForwardOwnership(Context c){context=c;}'+shipping_method('AndroidForwardingMaster.java','private Network ownedVpnNetwork()')+'Network inspect(){return ownedVpnNetwork();}}'
with tempfile.TemporaryDirectory(prefix='rvpn-guard-idle-') as tmp:
    base=Path(tmp)
    for name,text in SOURCES.items():
        p=base/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)
    shutil.copyfile(JAVA/'AndroidVpnMutationGuard.java',base/'com/eabusham/routervpn/AndroidVpnMutationGuard.java')
    subprocess.run(['javac','-d',str(base),*[str(p) for p in base.rglob('*.java')]],check=True,timeout=30)
    subprocess.run(['java','-cp',str(base),'com.eabusham.routervpn.GuardHarness'],check=True,timeout=30)
    for name in ('AndroidVpnMutationGuard','HomeOwnership','ForwardOwnership'):
        target=base/'com/eabusham/routervpn'/f'{name}.java';original=target.read_text()
        changed=original.replace('Build.VERSION_CODES.R','Build.VERSION_CODES.Q');assert changed!=original
        target.write_text(changed)
        subprocess.run(['javac','-d',str(base),*[str(p) for p in base.rglob('*.java')]],check=True,timeout=30)
        result=subprocess.run(['java','-cp',str(base),'com.eabusham.routervpn.GuardHarness'],capture_output=True,text=True,timeout=30)
        assert result.returncode!=0 and ('API29 mutation guard called API30' in result.stderr or 'getOwnerUid requires API30' in result.stderr),result.stdout+result.stderr
        target.write_text(original)
    print('Android getOwnerUid API29 regression negatives: all three rejected')
