#!/usr/bin/env python3
"""Type-check the full shipping layered service against API-boundary doubles.

Unlike the syntax gate, javac resolves every name, override and checked exception.
The actual APK build still checks the real SDK/AAR. No VPN, socket or service runs.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
SERVICE = ROOT / 'app/src/main/java/com/eabusham/routervpn/LayeredVpnService.java'
STUBS = {}
def stub(package, name, body, kind='class', imports=''):
    STUBS[package.replace('.', '/')+'/'+name+'.java'] = 'package '+package+';\n'+imports+'\npublic '+kind+' '+name+' '+body

stub('android.content','Context','''{ public static final String CONNECTIVITY_SERVICE="c",NOTIFICATION_SERVICE="n"; public static final int MODE_PRIVATE=0;
 public Object getSystemService(String name){return null;} public java.io.File getFilesDir(){return null;} public java.io.File getCacheDir(){return null;}
 public SharedPreferences getSharedPreferences(String a,int b){return null;} public android.content.pm.PackageManager getPackageManager(){return null;} }''')
stub('android.content','SharedPreferences','''{ Editor edit(); interface Editor {Editor putString(String a,String b);void apply();} }''','interface')
stub('android.content','Intent','{ public String getAction(){return "";} public long getLongExtra(String a,long b){return b;} public String getStringExtra(String a){return "";} }')
stub('android.content.pm','PackageManager','{ public static class NameNotFoundException extends Exception {} public String[] getPackagesForUid(int uid){return null;} }')
stub('android.app','Service','''extends android.content.Context {public static final int START_NOT_STICKY=2,STOP_FOREGROUND_REMOVE=1;
 public void onCreate(){} public int onStartCommand(android.content.Intent i,int f,int s){return 2;} public void onDestroy(){} public void stopSelf(){}
 public void stopForeground(int f){} public void startForeground(int i,Notification n){} }''')
stub('android.app','Notification','''{public static class Builder { public Builder(android.content.Context c){} public Builder(android.content.Context c,String s){}
 public Builder setContentTitle(String s){return this;} public Builder setContentText(String s){return this;} public Builder setSmallIcon(int i){return this;} public Builder setOngoing(boolean b){return this;} public Notification build(){return new Notification();} }}''')
stub('android.app','NotificationChannel','{ public NotificationChannel(String id,String name,int level){} }')
stub('android.app','NotificationManager','{public static final int IMPORTANCE_LOW=1;public void createNotificationChannel(NotificationChannel c){} }')
stub('android','R','{public static final class drawable{public static final int ic_dialog_info=1;} }')
stub('android.os','Build','{public static class VERSION {public static int SDK_INT=36;} public static class VERSION_CODES { public static final int O=26,Q=29,TIRAMISU=33;} }')
stub('android.os','Handler','{public Handler(Looper l){} public boolean post(Runnable r){return true;} public boolean postDelayed(Runnable r,long delay){return true;} public void removeCallbacks(Runnable r){} }')
stub('android.os','Looper','{public static Looper getMainLooper(){return null;} }')
stub('android.os','ParcelFileDescriptor','implements java.io.Closeable {public java.io.FileDescriptor getFileDescriptor(){return null;} public int getFd(){return 1;} public void close() throws java.io.IOException {} }')
stub('android.os','Process','{public static final int INVALID_UID=-1;}')
stub('android.system','OsConstants','{public static final int IFF_UP=1,IFF_RUNNING=2,IFF_LOOPBACK=4,IFF_POINTOPOINT=8,IFF_MULTICAST=16;}')
stub('android.util','Base64','{public static final int NO_WRAP=1;public static String encodeToString(byte[] b,int f){return "";} }')
stub('android.util','Log','{public static int d(String a,String b){return 0;} public static int w(String a,String b){return 0;} public static int w(String a,String b,Throwable t){return 0;} public static int e(String a,String b,Throwable t){return 0;} }')
stub('android.net','Network','{}')
stub('android.net','IpPrefix','{ public IpPrefix(java.net.InetAddress a,int p){} }')
stub('android.net','NetworkCapabilities','{public static final int TRANSPORT_VPN=1,TRANSPORT_WIFI=2,TRANSPORT_CELLULAR=3,TRANSPORT_ETHERNET=4,NET_CAPABILITY_NOT_METERED=5,NET_CAPABILITY_NOT_RESTRICTED=6; public boolean hasTransport(int n){return false;} public boolean hasCapability(int n){return true;} }')
stub('android.net','LinkProperties','{public String getInterfaceName(){return "";} public java.util.List<String> getLinkAddresses(){return java.util.List.of();} public java.util.List<java.net.InetAddress> getDnsServers(){return java.util.List.of();} }')
stub('android.net','ConnectivityManager','''{public Network[] getAllNetworks(){return new Network[0];} public Network getActiveNetwork(){return null;}
 public NetworkCapabilities getNetworkCapabilities(Network n){return null;}public LinkProperties getLinkProperties(Network n){return null;}
 public int getConnectionOwnerUid(int p,java.net.InetSocketAddress a,java.net.InetSocketAddress b){return 1;}
 public void registerDefaultNetworkCallback(NetworkCallback c){} public void unregisterNetworkCallback(NetworkCallback c){}
 public static class NetworkCallback {public void onAvailable(Network n){}public void onLost(Network n){}public void onCapabilitiesChanged(Network n,NetworkCapabilities c){}public void onLinkPropertiesChanged(Network n,LinkProperties p){}} }''')
stub('android.net','VpnService','''extends android.app.Service {public static android.content.Intent prepare(android.content.Context c){return null;}
 public boolean protect(int fd){return true;} public boolean isAlwaysOn(){return true;}public boolean isLockdownEnabled(){return true;}public void onRevoke(){}
 public class Builder {public Builder setSession(String s){return this;}public Builder setMtu(int n){return this;}public Builder setMetered(boolean b){return this;}
 public Builder addAddress(String s,int p){return this;}public Builder addDnsServer(String s){return this;}public Builder addRoute(IpPrefix p){return this;}public Builder addRoute(String a,int p){return this;}public Builder excludeRoute(IpPrefix p){return this;}
 public Builder addAllowedApplication(String s)throws android.content.pm.PackageManager.NameNotFoundException{return this;}public Builder addDisallowedApplication(String s)throws android.content.pm.PackageManager.NameNotFoundException{return this;}
 public android.os.ParcelFileDescriptor establish(){return null;} } }''')
stub('org.json','JSONObject','{public JSONObject(String s)throws Exception {} public String optString(String a,String b){return b;} public boolean optBoolean(String a,boolean b){return b;} }')
PKG='io.nekohasekai.libbox'
for name in ('LocalDNSTransport','WIFIState','Notification','NeighborUpdateListener','ShellSession','PlatformUser','BridgeSession','BridgeOptions','OverrideOptions','SystemProxyStatus'):stub(PKG,name,'{}')
stub(PKG,'StringIterator','{int len();boolean hasNext();String next();}','interface')
stub(PKG,'NetworkInterfaceIterator','{boolean hasNext();NetworkInterface next();}','interface')
stub(PKG,'RoutePrefixIterator','{boolean hasNext();RoutePrefix next();}','interface')
stub(PKG,'RoutePrefix','{public String address(){return "";}public int prefix(){return 0;} }')
stub(PKG,'InterfaceUpdateListener','{void updateDefaultInterface(String name,int index,boolean expensive,boolean constrained);}','interface')
stub(PKG,'ConnectionOwner','{public void setUserId(int id){}public void setUserName(String s){}public void setAndroidPackageNames(StringIterator s){} }')
stub(PKG,'NetworkInterface','{public void setName(String s){} public void setIndex(int i){} public void setMTU(int m){}public void setAddresses(StringIterator a){}public void setFlags(int f){}public void setDNSServer(StringIterator s){}public void setType(int t){}public void setMetered(boolean m){} }')
stub(PKG,'SetupOptions','{public void setBasePath(String s){}public void setWorkingPath(String s){}public void setTempPath(String s){}public void setFixAndroidStack(boolean b){}public void setLogMaxLines(int n){}public void setDebug(boolean b){} }')
stub(PKG,'TunOptions','''{public int getMTU(){return 1280;}public boolean getAutoRoute(){return true;} public StringIterator getDNSServerAddress(){return null;}public StringIterator getIncludePackage(){return null;}public StringIterator getExcludePackage(){return null;}
'''+''.join('public RoutePrefixIterator '+method+'(){return null;}' for method in ('getInet4Address','getInet6Address','getInet4RouteAddress','getInet6RouteAddress','getInet4RouteExcludeAddress','getInet6RouteExcludeAddress','getInet4RouteRange','getInet6RouteRange'))+'}')
stub(PKG,'RouterMultihop','{public void networkChanged(){}public boolean healthy(){return true;}public String progressJSON(){return "";}public String config(){return "";}public void run(CommandServer c)throws Exception{}public void close()throws Exception{} }')
stub(PKG,'RouterHopMeasurement','{public void networkChanged(){}public void start(String id,long size)throws Exception{}public void cancel(String id){}public String statusJSON(){return "";}public void close()throws Exception{} }')
stub(PKG,'Libbox','''{public static final int InterfaceTypeOther=0,InterfaceTypeWIFI=1,InterfaceTypeCellular=2,InterfaceTypeEthernet=3;
 public static void setup(SetupOptions o)throws Exception{}public static void checkConfig(String c)throws Exception{}
 public static long routerStartPerformance(CommandServer s)throws Exception{return 0;}public static String routerPerformanceFailure(CommandServer s){return "";}public static void routerInvalidatePerformance(CommandServer s){}
 public static RouterMultihop newRouterMultihop(String c,String m)throws Exception{return null;}public static RouterHopMeasurement newRouterHopMeasurement(CommandServer c,String m)throws Exception{return null;} }''')
stub(PKG,'CommandServer','{public CommandServer(PlatformInterface p,CommandServerHandler h)throws Exception{}public void start()throws Exception{}public void startOrReloadService(String c,OverrideOptions o)throws Exception{}public void closeService()throws Exception{}public void close(){}public void resetNetwork(){} }')
stub(PKG,'CommandServerHandler','{void serviceStop();void serviceReload();SystemProxyStatus getSystemProxyStatus();void setSystemProxyEnabled(boolean b);void writeDebugMessage(String s);}','interface')
# Explicit independent interface signatures: never derived from the class under test.
stub(PKG,'PlatformInterface','''{
 LocalDNSTransport localDNSTransport();boolean usePlatformAutoDetectInterfaceControl();void autoDetectInterfaceControl(int fd)throws Exception;int openTun(TunOptions o)throws Exception;
 boolean useProcFS();ConnectionOwner findConnectionOwner(int p,String a,int b,String c,int d)throws Exception;
 void startDefaultInterfaceMonitor(InterfaceUpdateListener l)throws Exception;void closeDefaultInterfaceMonitor(InterfaceUpdateListener l)throws Exception;
 NetworkInterfaceIterator getInterfaces()throws Exception;boolean underNetworkExtension();boolean includeAllNetworks();WIFIState readWIFIState();void clearDNSCache();void sendNotification(Notification n)throws Exception;
 void cancelNotification(String identifier,int typeID);void startNeighborMonitor(NeighborUpdateListener l)throws Exception;void closeNeighborMonitor(NeighborUpdateListener l)throws Exception;
 void registerMyInterface(String s);boolean usePlatformShell();void checkPlatformShell()throws Exception;
 ShellSession openShellSession(PlatformUser user,String command,StringIterator env,String term,int rows,int cols)throws Exception;
 PlatformUser lookupUser(String user)throws Exception;String lookupSFTPServer()throws Exception;String readSystemSSHHostKey()throws Exception;
 String tailscaleHostname();boolean usePlatformBridge();BridgeSession createBridge(BridgeOptions o)throws Exception;void triggerNativeCrash()throws Exception;int connectSSHAgent()throws Exception;
}''','interface')
APP='com.eabusham.routervpn'
stub(APP,'AndroidServiceStopConfirmation','{public static final String EXTRA_COMMAND="stop";public static void acknowledge(String k,long c){} }')
stub(APP,'AndroidKillSwitchPolicy','{public static final String SESSION_MARKER="kill-switch";public static String requirementMessage(){return "";} }')
stub(APP,'AndroidMTUSession','{interface Failure{void abort(AndroidMTUSession owner);}public AndroidMTUSession(android.content.Context c,Failure f){} public void activate(io.nekohasekai.libbox.CommandServer c,String config,String metadata){}public String request(String a,String b,String c)throws Exception{return "";}public boolean running(){return false;}public void drainForMeasurement()throws Exception{}public void networkChanged(){}public void close()throws Exception{}public void beforeOpen()throws Exception{}public void established(int mtu)throws Exception{}public void registered(String name){}public boolean unchangedPhysicalPath(){return false;}public void checkNetwork(){} }')
stub(APP,'AndroidStartLayerRelay','implements java.io.Closeable{public static AndroidStartLayerRelay startIfConfigured(android.content.Context c,java.io.File f,java.util.function.Consumer<String> failure)throws Exception{return null;}public void close(){} }')

def main():
    if not shutil.which('javac'):
        raise RuntimeError('A JDK is required; whole-service type validation must not be skipped')
    with tempfile.TemporaryDirectory(prefix='routervpn-layered-types-') as directory:
        root=Path(directory)
        for path,source in STUBS.items():
            f=root/path;f.parent.mkdir(parents=True,exist_ok=True);f.write_text(source,encoding='utf-8')
        target=root/'com/eabusham/routervpn/LayeredVpnService.java'
        text=SERVICE.read_text();target.write_text(text,encoding='utf-8')
        sources=[str(p) for p in root.rglob('*.java')]
        args=['javac','--release','17','-proc:none','-encoding','UTF-8','-d',str(root/'classes')]+sources
        subprocess.run(args,check=True,timeout=40)
        # The old parser-only gate accepted each of these type failures.
        controls=[('missing JSON import','import org.json.JSONObject;',''),
                  ('out-of-scope session','File executionFile=new File(session,','File executionFile=new File(missingSession,'),
                  ('duplicate override','@Override public void sendNotification','@Override @Override public void sendNotification'),
                  ('incompatible checked exception','void cancelNotification(String identifier, int typeID) {','void cancelNotification(String identifier, int typeID) throws Exception {')]
        for label,old,new in controls:
            assert text.count(old)==1,(label,text.count(old))
            target.write_text(text.replace(old,new),encoding='utf-8')
            failed=subprocess.run(args,capture_output=True,text=True,timeout=40)
            assert failed.returncode!=0 and 'LayeredVpnService.java:' in failed.stderr,label+' escaped the complete type check'
    print('Full Android LayeredVpnService type checking: PASS; 4 negative controls rejected (SDK/native handles doubled).')

if __name__=='__main__':main()
