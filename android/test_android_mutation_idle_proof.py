#!/usr/bin/env python3
"""Run the actual mutation guard with deterministic engine/network boundary doubles."""
from pathlib import Path
import shutil,subprocess,tempfile
ROOT=Path(__file__).resolve().parents[1]
JAVA=ROOT/'android/app/src/main/java/com/eabusham/routervpn'
SOURCES={
'android/content/Context.java':'''package android.content; public class Context {public static final String CONNECTIVITY_SERVICE="connectivity"; public Object getSystemService(String key){return new android.net.ConnectivityManager();}}''',
'android/net/ConnectivityManager.java':'''package android.net; public class ConnectivityManager {public Network getActiveNetwork(){return null;} public NetworkCapabilities getNetworkCapabilities(Network n){return null;}}''',
'android/net/Network.java':'package android.net; public class Network {}',
'android/net/NetworkCapabilities.java':'''package android.net; public class NetworkCapabilities {public static final int TRANSPORT_VPN=4; public boolean hasTransport(int t){return false;} public int getOwnerUid(){return 1000;}}''',
'android/os/Build.java':'package android.os; public class Build {public static class VERSION {public static int SDK_INT=35;} public static class VERSION_CODES {public static final int Q=29;}}',
'android/os/Process.java':'package android.os; public class Process {public static int myUid(){return 1000;}}',
'com/wireguard/android/backend/Tunnel.java':'package com.wireguard.android.backend; public interface Tunnel {enum State {DOWN,UP}}',
'org/amnezia/awg/backend/Tunnel.java':'package org.amnezia.awg.backend; public interface Tunnel {enum State {DOWN,UP}}',
'com/eabusham/routervpn/GuardBoundaries.java':r'''package com.eabusham.routervpn;
import android.content.Context;
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
public final class GuardHarness {
    static int failed;static final Context context=new Context();
    static AndroidRuntimeRegistry reset(){AndroidHomeStateStore.home=new AndroidHomeStateStore.Snapshot();return AndroidRuntimeRegistry.current=new AndroidRuntimeRegistry();}
    static void check(String name,boolean expected){boolean actual=AndroidVpnMutationGuard.isBusy(context);if(actual!=expected){failed++;System.out.println("FAIL "+name+": busy="+actual);}else System.out.println("PASS "+name);}
    public static void main(String[] args){
        AndroidRuntimeRegistry e=reset();check("completed failed session releases cached orchestrator marker",false);
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
        if(failed>0)throw new AssertionError(failed+" mutation idle-proof regressions");
        System.out.println("Android actual mutation idle-proof behavior: PASS");
    }
}
'''
}
with tempfile.TemporaryDirectory(prefix='rvpn-guard-idle-') as tmp:
    base=Path(tmp)
    for name,text in SOURCES.items():
        p=base/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)
    shutil.copyfile(JAVA/'AndroidVpnMutationGuard.java',base/'com/eabusham/routervpn/AndroidVpnMutationGuard.java')
    subprocess.run(['javac','-d',str(base),*[str(p) for p in base.rglob('*.java')]],check=True,timeout=30)
    subprocess.run(['java','-cp',str(base),'com.eabusham.routervpn.GuardHarness'],check=True,timeout=30)
