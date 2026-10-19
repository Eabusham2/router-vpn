#!/usr/bin/env python3
"""Run the complete shipping service with real MAX preparation and Go graphs.

Android VPN/descriptor/network callbacks and Libbox runtime handles are boundary
doubles. The full service, owner, exact-source checks and shutdown logic execute;
no Android kernel VPN or remote MAX negotiation is claimed.
"""
from pathlib import Path
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / 'android/app/src/main/java/com/eabusham/routervpn'

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

F = module('max_preparation_service_fixture', 'android/test_android_max_preparation.py')
B = module('max_service_types', 'android/test_android_layered_service_compile.py')
P = F.P
S = P.M.STUBS
preserve = {'org/json/JSONObject.java', 'io/nekohasekai/libbox/Libbox.java', 'io/nekohasekai/libbox/RouterMultihop.java',
            'com/eabusham/routervpn/AndroidMAXProfilePreparation.java', 'com/eabusham/routervpn/AndroidMultihopStartLayer.java',
            'com/eabusham/routervpn/RouterPQNative.java', 'com/eabusham/routervpn/AndroidKillSwitchPolicy.java',
            'android/net/Network.java', 'android/net/NetworkCapabilities.java', 'android/net/ConnectivityManager.java',
            'android/net/LinkProperties.java', 'android/util/Base64.java'}
for path, source in B.STUBS.items():
    if path not in preserve:
        S[path] = source
S['com/eabusham/routervpn/LayeredVpnService.java'] = (JAVA/'LayeredVpnService.java').read_text()
S['com/eabusham/routervpn/AndroidServiceStopConfirmation.java'] = (JAVA/'AndroidServiceStopConfirmation.java').read_text()
boundary = S['com/eabusham/routervpn/Boundaries.java'].replace('final class AndroidKillSwitchPolicy {', 'final class AndroidKillSwitchPolicy {static String requirementMessage(){return "lockdown required";}')
start = boundary.index('final class AndroidStartLayerRelay {')
end = boundary.index('final class RouterPQNative {', start)
boundary = boundary[:start] + boundary[end:]
start = boundary.index('final class LayeredVpnService {')
end = boundary.index('final class XrayVpnService {', start)
S['com/eabusham/routervpn/Boundaries.java'] = boundary[:start] + boundary[end:]
S['com/eabusham/routervpn/AndroidStartLayerRelay.java'] = S['com/eabusham/routervpn/AndroidStartLayerRelay.java'].replace('public interface SocketProtector', 'public static final String SESSION_FILE="start-layer.json";public static final int LISTEN_PORT=18389,SERVER_PORT=8389;public interface SocketProtector')
S['android/util/Log.java'] = S['android/util/Log.java'].replace('e(String a,String b,Throwable t){return 0;}', 'e(String a,String b,Throwable t){last=t;return 0;}public static Throwable last;')
S['android/content/Context.java'] = r'''package android.content;
public class Context {
 public static final String CONNECTIVITY_SERVICE="c",NOTIFICATION_SERVICE="n";public static final int MODE_PRIVATE=0;
 public java.io.File root;public android.net.ConnectivityManager connectivity=new android.net.ConnectivityManager();
 public Context(){}public Context(java.io.File file){root=file;}public Context getApplicationContext(){return this;}
 public Object getSystemService(String name){return name.equals(CONNECTIVITY_SERVICE)?connectivity:new android.app.NotificationManager();}
 public java.io.File getFilesDir(){return root;}public java.io.File getCacheDir(){return new java.io.File(root,"cache");}public java.io.File getNoBackupFilesDir(){return new java.io.File(root,"no-backup");}
 public Object startService(Intent i){return null;}public Object startForegroundService(Intent i){return null;}
 public SharedPreferences getSharedPreferences(String a,int b){return new SharedPreferences(){public String getString(String k,String d){return d;}public Editor edit(){return new Editor(){public Editor putString(String k,String v){return this;}public void apply(){}};}};}
 public android.content.pm.PackageManager getPackageManager(){return new android.content.pm.PackageManager();}
}'''
S['android/content/SharedPreferences.java'] = S['android/content/SharedPreferences.java'].replace('{ Editor edit();', '{String getString(String k,String d); Editor edit();')
S['android/content/Intent.java'] = r'''package android.content;public class Intent {
 private String action;private final java.util.Map<String,Object> values=new java.util.HashMap<>();
 public Intent(android.content.Context c,Class<?> type){}public Intent setAction(String value){action=value;return this;}public String getAction(){return action;}
 public Intent putExtra(String k,String v){values.put(k,v);return this;}public Intent putExtra(String k,long v){values.put(k,v);return this;}
 public long getLongExtra(String k,long d){return values.containsKey(k)?((Number)values.get(k)).longValue():d;}public String getStringExtra(String k){return (String)values.get(k);}
}'''
S['android/net/Network.java'] = S['android/net/Network.java'].replace('public final long id;', r'''public int fdBinds,tcpBinds,udpBinds;public Runnable bindingChange;
 public void bindSocket(java.io.FileDescriptor fd){if(!fd.valid())throw new AssertionError("invalid borrowed descriptor");fdBinds++;if(bindingChange!=null)bindingChange.run();}
 public void bindSocket(java.net.Socket s){tcpBinds++;if(bindingChange!=null)bindingChange.run();}public void bindSocket(java.net.DatagramSocket s){udpBinds++;if(bindingChange!=null)bindingChange.run();}
 public final long id;''')
S['android/net/NetworkCapabilities.java'] = S['android/net/NetworkCapabilities.java'].replace('NET_CAPABILITY_INTERNET=12,', 'NET_CAPABILITY_NOT_METERED=11,NET_CAPABILITY_NOT_RESTRICTED=13,NET_CAPABILITY_INTERNET=12,')
S['android/net/ConnectivityManager.java'] = S['android/net/ConnectivityManager.java'].replace('public Network active=', r'''
 public int getConnectionOwnerUid(int p,java.net.InetSocketAddress a,java.net.InetSocketAddress b){return 1;}
 public void registerDefaultNetworkCallback(NetworkCallback c){}public void unregisterNetworkCallback(NetworkCallback c){}
 public static class NetworkCallback{public void onAvailable(Network n){}public void onLost(Network n){}public void onCapabilitiesChanged(Network n,NetworkCapabilities c){}public void onLinkPropertiesChanged(Network n,LinkProperties p){}}
 public Network active=''')
S['android/os/ParcelFileDescriptor.java'] = r'''package android.os;public class ParcelFileDescriptor implements java.io.Closeable {
 public static ParcelFileDescriptor duplicate,lastTun;public boolean closed;private final java.io.FileInputStream file;
 public ParcelFileDescriptor(){try{file=new java.io.FileInputStream("/dev/null");}catch(Exception e){throw new AssertionError(e);}}
 public static ParcelFileDescriptor fromFd(int fd){duplicate=new ParcelFileDescriptor();return duplicate;}
 public java.io.FileDescriptor getFileDescriptor(){try{return file.getFD();}catch(Exception e){throw new AssertionError(e);}}public int getFd(){return 123;}
 public void close()throws java.io.IOException{closed=true;file.close();}
}'''
S['android/net/VpnService.java'] = S['android/net/VpnService.java'].replace('public boolean protect(int fd){return true;}', 'public int protections;public boolean refuseProtect;public boolean protect(int fd){protections++;return !refuseProtect;}').replace('public android.os.ParcelFileDescriptor establish(){return null;}', r'''
 public android.os.ParcelFileDescriptor establish(){android.net.Network physical=connectivity.active;android.net.Network vpn=new android.net.Network(202);vpn.caps.vpn=true;connectivity.networks=new android.net.Network[]{physical,vpn};connectivity.active=vpn;return android.os.ParcelFileDescriptor.lastTun=new android.os.ParcelFileDescriptor();}''')
S['io/nekohasekai/libbox/RoutePrefix.java'] = '''package io.nekohasekai.libbox;public class RoutePrefix{public String address(){return "10.77.0.2";}public int prefix(){return 32;}}'''
S['io/nekohasekai/libbox/TunOptions.java'] = r'''package io.nekohasekai.libbox;public class TunOptions{
 public int getMTU(){return 1280;}public boolean getAutoRoute(){return true;}
 private StringIterator strings(boolean dns){return new StringIterator(){boolean more=dns;public int len(){return dns?1:0;}public boolean hasNext(){return more;}public String next(){more=false;return "10.77.0.1";}};}
 private RoutePrefixIterator routes(boolean address){return new RoutePrefixIterator(){boolean more=address;public boolean hasNext(){return more;}public RoutePrefix next(){more=false;return new RoutePrefix();}};}
 public StringIterator getDNSServerAddress(){return strings(true);}public StringIterator getIncludePackage(){return strings(false);}public StringIterator getExcludePackage(){return strings(false);}
 public RoutePrefixIterator getInet4Address(){return routes(true);}public RoutePrefixIterator getInet6Address(){return routes(false);}
''' + ''.join('public RoutePrefixIterator '+name+'(){return routes(false);}' for name in ('getInet4RouteAddress', 'getInet6RouteAddress', 'getInet4RouteExcludeAddress', 'getInet6RouteExcludeAddress', 'getInet4RouteRange', 'getInet6RouteRange')) + '}'
S['io/nekohasekai/libbox/RouterMultihop.java'] = S['io/nekohasekai/libbox/RouterMultihop.java'].replace('public void close(){}', 'public void close(){}public void networkChanged(){}public boolean healthy(){return true;}public String progressJSON(){return "";}public void run(CommandServer c){}')
S['io/nekohasekai/libbox/CommandServer.java'] = r'''package io.nekohasekai.libbox;public class CommandServer{
 public static int created;public static CommandServer last;public int closes,uncheckedCloses;private final PlatformInterface platform;
 public CommandServer(PlatformInterface p,CommandServerHandler h){platform=p;last=this;created++;}public void start(){}
 public void startOrReloadService(String c,OverrideOptions o)throws Exception{platform.autoDetectInterfaceControl(41);platform.openTun(new TunOptions());}
 public void closeService(){uncheckedCloses++;}public void close(){closes++;}public void resetNetwork(){}
}'''
S['io/nekohasekai/libbox/Libbox.java'] = S['io/nekohasekai/libbox/Libbox.java'].replace(' public static String routerMAXMultihopBase(', r'''
 public static final int InterfaceTypeOther=0,InterfaceTypeWIFI=1,InterfaceTypeCellular=2,InterfaceTypeEthernet=3;
 public static boolean failClose;public static int checkedCloses;public static Runnable performanceBoundary;
 public static void setup(SetupOptions o){}public static void routerTorSetStateDirectory(String p){}
 public static void routerStrategyCloseService(CommandServer s){checkedCloses++;if(failClose)throw new IllegalStateException("retained native owner");}
 public static long routerStartPerformance(CommandServer s){if(performanceBoundary!=null)performanceBoundary.run();return 0;}
 public static String routerPerformanceFailure(CommandServer s){return "";}public static void routerInvalidatePerformance(CommandServer s){}
 public static RouterHopMeasurement newRouterHopMeasurement(CommandServer c,String m){return new RouterHopMeasurement();}
 public static String routerMAXMultihopBase(''', 1)

P.HARNESS = P.HARNESS[:P.HARNESS.index(' public static void main(')]
old_stage = 'folder=Files.createTempDirectory(context.getFilesDir().toPath(),"stage-").toFile();'
assert P.HARNESS.count(old_stage) == 1
P.HARNESS = P.HARNESS.replace(old_stage, 'folder=context.getFilesDir().toPath().resolve("layered-sessions").resolve(session).toFile();Files.createDirectories(folder.toPath());')
P.HARNESS += r'''
 static java.lang.reflect.Field serviceField(String name)throws Exception{var value=LayeredVpnService.class.getDeclaredField(name);value.setAccessible(true);return value;}
 static String state(LayeredVpnService service)throws Exception{return (String)serviceField("state").get(service);}
 static void state(LayeredVpnService service,String expected)throws Exception{for(int i=0;i<400;i++){if(state(service).equals(expected))return;Thread.sleep(10);}throw new AssertionError("expected service "+expected+", got "+state(service));}
 static final java.util.List<LayeredVpnService> services=new java.util.ArrayList<>();
 static LayeredVpnService service(Owned owned)throws Exception{
  LayeredVpnService service=new LayeredVpnService();service.root=owned.context.root;((Context)service).connectivity=owned.context.connectivity;service.onCreate();services.add(service);return service;
 }
 static void start(LayeredVpnService service,Owned o){service.onStartCommand(new android.content.Intent(service,LayeredVpnService.class).setAction(LayeredVpnService.ACTION_START).putExtra(LayeredVpnService.EXTRA_SESSION_ID,o.session).putExtra(LayeredVpnService.EXTRA_MODE_ID,o.mode).putExtra(AndroidMAXProfilePreparation.EXTRA_OWNER,o.owner.identity),0,1);}
 static void stop(LayeredVpnService service){service.onStartCommand(new android.content.Intent(service,LayeredVpnService.class).setAction(LayeredVpnService.ACTION_STOP),0,2);}
 static void settle(LayeredVpnService service)throws Exception{((java.util.concurrent.ExecutorService)serviceField("executor").get(service)).submit(()->{}).get(3,java.util.concurrent.TimeUnit.SECONDS);}
 static void fresh(){reset();io.nekohasekai.libbox.CommandServer.created=0;io.nekohasekai.libbox.CommandServer.last=null;io.nekohasekai.libbox.Libbox.failClose=false;io.nekohasekai.libbox.Libbox.checkedCloses=0;io.nekohasekai.libbox.Libbox.performanceBoundary=null;io.nekohasekai.libbox.Libbox.afterCheck=null;}
 static void serviceSuccess(Path root)throws Exception{
  fresh();Owned o=new Owned(root,"max-quic-awg","aes-256-gcm+xor-whitening");o.compile();o.stage();LayeredVpnService service=service(o);android.net.Network physical=o.context.connectivity.active;
  start(service,o);state(service,"UP");check(io.nekohasekai.libbox.CommandServer.created==1&&physical.fdBinds==1,"native socket bypassed captured Network before TUN");
  check(android.os.ParcelFileDescriptor.duplicate.closed,"borrowed FD duplicate leaked");check(!AndroidMAXProfilePreparation.busy(),"runtime started before resolver registry drained");
  service.autoDetectInterfaceControl(77);service.protectRelaySocket(new java.net.Socket());service.protectRelaySocket((java.net.DatagramSocket)null);
  check(physical.fdBinds==2&&physical.tcpBinds==1&&physical.udpBinds==1,"active VPN socket or relay escaped captured physical receiver");
  service.refuseProtect=true;reject(()->service.autoDetectInterfaceControl(78));check(physical.fdBinds==2,"refused protection still opened physical socket");service.refuseProtect=false;
  var server=io.nekohasekai.libbox.CommandServer.last;var tun=android.os.ParcelFileDescriptor.lastTun;
  io.nekohasekai.libbox.Libbox.failClose=true;stop(service);state(service,"STOPPING");Thread.sleep(50);
  check(serviceField("commandServer").get(service)==server&&serviceField("maxSession").get(service)!=null&&!tun.closed,"failed MAX drain released native/TUN/session owner");
  check(server.closes==0&&server.uncheckedCloses==0&&o.folder.exists(),"unconfirmed MAX cleanup was acknowledged");
  io.nekohasekai.libbox.Libbox.failClose=false;stop(service);state(service,"DOWN");
  check(server.closes==1&&server.uncheckedCloses==0&&tun.closed&&serviceField("maxSession").get(service)==null,"retry did not close the exact retained native owner");service.onDestroy();o.unchanged();
 }
 static void cancelledClaim(Path root)throws Exception{
  fresh();Owned o=new Owned(root,"max-tls-wg","off");o.compile();o.stage();var state=io.nekohasekai.libbox.RouterMAXProfileRequest.next;
  state.closeEntered=new java.util.concurrent.CountDownLatch(1);state.closeRelease=new java.util.concurrent.CountDownLatch(1);LayeredVpnService service=service(o);start(service,o);waitFor(state.closeEntered);
  long before=System.nanoTime();stop(service);check(System.nanoTime()-before<250_000_000L,"service STOP waited for MAX cleanup");
  check(io.nekohasekai.libbox.CommandServer.created==0&&AndroidMAXProfilePreparation.busy(),"Box started before retained resolver close");
  state.closeRelease.countDown();state(service,"DOWN");check(io.nekohasekai.libbox.CommandServer.created==0,"cancelled claim constructed a native runtime");service.onDestroy();
 }
 static void startupMutation(Path root)throws Exception{
  for(String moment:new String[]{"before-box","before-up"})for(String what:new String[]{"source","network","home","stop"}){
   fresh();Owned o=new Owned(root,"max-quic-wg","off");o.compile();o.stage();LayeredVpnService service=service(o);
   Runnable change=()->{try{switch(what){case "source":Files.writeString(o.source.toPath(),"{}");break;case "network":o.context.connectivity.networks=new android.net.Network[0];break;case "home":AndroidHomeStateStore.value.sessionId="new-session";break;default:stop(service);}}catch(Exception failure){throw new RuntimeException(failure);}};
   if(moment.equals("before-box"))io.nekohasekai.libbox.Libbox.afterCheck=change;else io.nekohasekai.libbox.Libbox.performanceBoundary=change;
   start(service,o);settle(service);state(service,what.equals("stop")?"DOWN":"FAILED");
   check(io.nekohasekai.libbox.CommandServer.created==(moment.equals("before-box")?0:1),"source/network/session changed across native start boundary: "+moment+"/"+what+" created="+io.nekohasekai.libbox.CommandServer.created+" error="+android.util.Log.last);
   check(serviceField("maxSession").get(service)==null&&serviceField("commandServer").get(service)==null,"failed startup retained an acknowledged owner");service.onDestroy();
  }
 }
 static void afterBindMutation(Path root)throws Exception{
  fresh();Owned o=new Owned(root,"max-tls-awg","off");o.compile();o.stage();LayeredVpnService service=service(o);android.net.Network physical=o.context.connectivity.active;start(service,o);state(service,"UP");
  physical.bindingChange=()->physical.links.privateName="different-resolver.example";reject(()->service.autoDetectInterfaceControl(19));check(physical.fdBinds==2,"post-bind network mutation case did not reach physical receiver");stop(service);state(service,"DOWN");service.onDestroy();
 }
 public static void main(String[]args)throws Exception{
  fixtures=new JSONObject(Files.readString(Path.of(System.getenv("ROUTERVPN_MAX_PROFILE_FIXTURES"))));Path root=Path.of(args[0]);
  try{serviceSuccess(root);cancelledClaim(root);startupMutation(root);afterBindMutation(root);noThreads();}finally{io.nekohasekai.libbox.Libbox.failClose=false;var owned=io.nekohasekai.libbox.RouterMAXProfileRequest.next;if(owned.closeRelease!=null)owned.closeRelease.countDown();AndroidMAXProfilePreparation.cancelActive();for(var service:services)service.onDestroy();}
  System.out.println("Android MAX full service ownership: PASS "+checks+" checks; actual Java/Go preparation with OS/native runtime handles doubled");
 }
}
'''

if __name__ == '__main__':
    F.main()
