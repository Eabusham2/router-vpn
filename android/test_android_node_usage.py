#!/usr/bin/env python3
"""Execute Android usage adoption through the shipping controller and private stores.

The full usage recorder, controller, Home owner, node/exit stores, catalog and
private-file primitive are compiled unchanged. Native VPN proof is an explicit
controllable boundary; these tests do not claim an Android device connection.
The Android Os adapter uses real Linux regular files, Unix stat, fsync and atomic
rename, including descriptor identity, to exercise the shipping I/O monitor.
"""
from pathlib import Path
import importlib.util
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / 'android/app/src/main/java/com/eabusham/routervpn'
spec = importlib.util.spec_from_file_location('usage_startup_boundaries', ROOT / 'android/test_android_startup_policy.py')
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)
P = S.P

OS = r'''package android.system;
import java.io.*;import java.nio.file.*;import java.nio.file.attribute.*;import java.util.*;import java.util.concurrent.*;
public final class Os {
 public static volatile String holdTarget="";public static volatile CountDownLatch renameEntered,renameRelease;
 private static StructStat stat(Path p,boolean follow)throws ErrnoException{try{Map<String,Object> a=Files.readAttributes(p,"unix:mode,dev,ino,size",follow?new LinkOption[0]:new LinkOption[]{LinkOption.NOFOLLOW_LINKS});return new StructStat(((Number)a.get("mode")).intValue(),((Number)a.get("dev")).longValue(),((Number)a.get("ino")).longValue(),((Number)a.get("size")).longValue());}catch(NoSuchFileException e){throw new ErrnoException("stat",OsConstants.ENOENT);}catch(IOException e){throw new ErrnoException("stat",5);}}
 public static StructStat lstat(String p)throws ErrnoException{return stat(Path.of(p),false);}
 public static StructStat fstat(FileDescriptor fd)throws Exception{var f=FileDescriptor.class.getDeclaredField("fd");f.setAccessible(true);return stat(Path.of("/proc/self/fd/"+f.getInt(fd)),true);}
 public static void chmod(String p,int mode)throws Exception{Files.setAttribute(Path.of(p),"unix:mode",mode,LinkOption.NOFOLLOW_LINKS);}
 public static void rename(String a,String b)throws Exception{if(b.equals(holdTarget)){renameEntered.countDown();if(!renameRelease.await(5,TimeUnit.SECONDS))throw new IOException("fixture rename barrier expired");}Files.move(Path.of(a),Path.of(b),StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);}
 public static void remove(String p)throws Exception{Files.delete(Path.of(p));}
}
'''

NATIVE = r'''
// Only native-engine readiness/proof is controlled. Source capture, permission,
// final Home adoption and all statistics persistence remain production code.
final class NativeUsageBoundary {
 static Context context;static Runnable pending,last,beforeFinish;static boolean fail,omitOwned;static String fault="";
 static void reset(Context c){context=c;pending=null;last=null;beforeFinish=null;fail=false;omitOwned=false;fault="";}
 static void finish(){Runnable action=pending;pending=null;if(action==null)throw new AssertionError("native boundary was not launched");last=action;action.run();}
 static void router(File f,String mode,AndroidModeOrchestrator.Callback cb){
  String id=AndroidHomeStateStore.nodeIdFromBundleFile(f),session=AndroidHomeStateStore.begin(context,mode,"wg","wg",id);if(!omitOwned)cb.owned(session);
  pending=()->{if(fail){AndroidHomeStateStore.failed(context,"controlled proof failure");cb.finished(false,"","proof failed");return;}AndroidHomeStateStore.connected(context,mode,"wg","wg","",id);alter();cb.finished(true,"wg","proved Router connection");};
 }
 static void multihop(AndroidNodeStore.Node a,AndroidNodeStore.Node b,String mode,String entry,AndroidMultihopRuntime.Callback cb){
  String session=AndroidHomeStateStore.beginMultihop(context,a.id,b.id,mode,entry);if(!omitOwned)cb.owned(session);cb.progress("Comparing captured Local and Server candidates");
  pending=()->{if(fail){AndroidHomeStateStore.failed(context,"controlled graph proof failure");cb.finished(false,"proof failed");return;}AndroidHomeStateStore.connectedMultihop(context,a.id,b.id,mode,entry);alter();cb.finished(true,"proved final multihop winner");};
 }
 static void imported(AndroidStandardExitStore.Entry a,AndroidNodeStore.Node b,String mode,AndroidMultihopRuntime.Callback cb){
  String session=AndroidHomeStateStore.beginMultihop(context,a.id,b.id,mode,a.protocol);if(!omitOwned)cb.owned(session);
  pending=()->{if(fail){AndroidHomeStateStore.failed(context,"controlled imported proof failure");cb.finished(false,"proof failed");return;}AndroidHomeStateStore.connectedMultihop(context,a.id,b.id,mode,a.protocol);alter();cb.finished(true,"proved imported Router path");};
 }
 static void external(File f,AndroidStandardExitStore.Entry a,AndroidStandardExitStore.Entry e,String entry,AndroidStandardExitRuntime.Callback cb){
  String id=a!=null?a.id:f==null?"":AndroidHomeStateStore.nodeIdFromBundleFile(f);boolean tor=AndroidTorProfile.isTor(e.protocol);
  String session=tor?AndroidHomeStateStore.beginTorExternal(context,e.id,e.name,e.protocol,id,entry):AndroidHomeStateStore.beginPolicyExternal(context,e.id,e.name,e.protocol,e.expectedPublicIp,id,entry);
  AndroidHomeStateStore.Snapshot owner=AndroidHomeStateStore.snapshot(context);if(!omitOwned)cb.owned(session);
  pending=()->{if(fail){AndroidHomeStateStore.failed(context,"controlled external proof failure");cb.finished(false,"proof failed");return;}boolean adopted=tor?AndroidHomeStateStore.connectedTorExternal(context,owner,"8.8.4.4"):AndroidHomeStateStore.connectedPolicyExternal(context,owner,"8.8.4.4");if(!adopted)throw new AssertionError("fixture Home adoption failed");alter();last=()->cb.finished(true,"proved external connection");last.run();};
 }
 static void alter(){if(fault.equals("owner"))AndroidHomeStateStore.begin(context,"replacement","wg","wg","other");if(fault.equals("proof"))AndroidHomeStateStore.failedPreservingOwnership(context,"proof invalidated");if(fault.equals("emergency"))AndroidHomeStateStore.warning(context,"Emergency Disconnect requested; retained guard");if(fault.equals("generation"))AndroidHomeStateStore.advancePathGeneration(context);if(fault.equals("path"))context.getSharedPreferences("routervpn_home_state_v1",0).edit().putString("active_node_id","other").apply();if(beforeFinish!=null)beforeFinish.run();}
}
final class AndroidModeOrchestrator {
 int starts;interface Callback{void progress(String m);void finished(boolean ok,String mode,String m);default void owned(String s){}default void proved(String s,String raw,String source){}}
 boolean isRunning(){return false;}void logical(File f,String m,Callback cb){starts++;NativeUsageBoundary.router(f,m,cb);}void auto(File f,boolean smart,Callback cb){logical(f,smart?"smart-auto":"auto",cb);}void all(File f,Callback cb){logical(f,"all",cb);}void custom(File f,List<String> layers,Callback cb){logical(f,"custom",cb);}void startup(File f,String m,String raw,String source,Callback cb){logical(f,m,cb);}
 String captureSource(File f,String session,String raw)throws Exception{return Files.readString(f.toPath());}void restoreCaptured(File f,String raw,String logical,String fallback,String source,Callback cb){logical(f,logical,cb);}void disconnectCaptured(String session,Callback cb){AndroidHomeStateStore.disconnected(NativeUsageBoundary.context);cb.finished(true,"","stopped");}void disconnect(Callback cb){disconnectCaptured("",cb);}
}
final class AndroidMultihopRuntime {
 AndroidStandardExitStore.Entry ordinary;
 AndroidStandardExitStore.Entry capturedOrdinaryEntry(AndroidHomeStateStore.Snapshot h){return ordinary;}
 void connectImported(AndroidStandardExitStore.Entry a,AndroidNodeStore.Node b,String mode,String execution,Callback cb){starts++;ordinary=a;NativeUsageBoundary.imported(a,b,mode,cb);}
 int starts;
 // MULTIHOP_CAPTURE_TYPES
 interface Callback{void progress(String s);void finished(boolean ok,String s);default void owned(String id){}}
 String activeExecution(){return "auto";}String activeSelectedExecution(){return "server";}
 void connectLast(AndroidNodeStore.Node a,AndroidNodeStore.Node b,StartupCapture capture,AndroidHomeStateStore.Snapshot idle,Callback cb){throw new AssertionError("not a usage acceptance path");}
 void restoreCaptured(AndroidNodeStore.Node a,AndroidNodeStore.Node b,RestoreCapture capture,AndroidHomeStateStore.Snapshot idle,Callback cb){connect(a,b,capture.owner.exitMode,capture.policy,capture.owner.entryMode,cb);}
 RestoreCapture captureRestore(AndroidNodeStore.Node a,AndroidNodeStore.Node b,AndroidHomeStateStore.Snapshot home)throws Exception{return new RestoreCapture("auto","server",home,a,b,"private-pins");}boolean captureCurrent(RestoreCapture capture){return capture.owner.matchesHome(AndroidHomeStateStore.snapshot(NativeUsageBoundary.context));}boolean restoredMatches(RestoreCapture capture,AndroidNodeStore.Node a,AndroidNodeStore.Node b,AndroidHomeStateStore.Snapshot home){return home.connected;}boolean disconnectAndDrainCaptured(String session){AndroidHomeStateStore.disconnected(NativeUsageBoundary.context);return true;}
 boolean isConnected(){return AndroidHomeStateStore.snapshot(NativeUsageBoundary.context).connected;}boolean isActiveOrTransitioning(){return false;}String activeEntryId(){return AndroidHomeStateStore.snapshot(NativeUsageBoundary.context).activeEntryId;}String activeExitId(){return AndroidHomeStateStore.snapshot(NativeUsageBoundary.context).activeExitId;}String activeEntryMode(){return AndroidHomeStateStore.snapshot(NativeUsageBoundary.context).activeEntryMode;}String activeExitMode(){return AndroidHomeStateStore.snapshot(NativeUsageBoundary.context).runtimeMode;}
 void disconnect(){AndroidHomeStateStore.disconnected(NativeUsageBoundary.context);}void connect(AndroidNodeStore.Node a,AndroidNodeStore.Node b,String mode,String execution,String entry,Callback cb){starts++;NativeUsageBoundary.multihop(a,b,mode,entry,cb);}List<NativeSingBoxController.ModeInfo> listSupportedExitModes(File f){return Collections.emptyList();}
}
final class AndroidStandardExitRuntime {
 interface Callback{void progress(String s);void finished(boolean ok,String s);default void owned(String id){}}
 int starts;String execution="local",selected="local";AndroidStandardExitStore.Entry ordinary;
 AndroidStandardExitStore.Entry capturedOrdinaryEntry(AndroidHomeStateStore.Snapshot s){return ordinary;}String capturedRequestedExecution(AndroidHomeStateStore.Snapshot s){return execution;}String capturedExternalExecution(AndroidHomeStateStore.Snapshot s){return selected;}
 void connectOrdinary(AndroidStandardExitStore.Entry a,AndroidStandardExitStore.Entry e,String execution,Callback cb){starts++;ordinary=a;this.execution=execution;selected="local";NativeUsageBoundary.external(null,a,e,AndroidExternalPolicy.protocol(a.protocol),cb);}
 void connect(File f,AndroidStandardExitStore.Entry e,String mode,String execution,Callback cb){starts++;this.execution=execution;selected=execution.equals("auto")?"server":execution;NativeUsageBoundary.external(f,null,e,mode,cb);}
 void connectDirect(AndroidStandardExitStore.Entry e,Callback cb){connect(null,e,"","local",cb);}void connect(File f,AndroidStandardExitStore.Entry e,String mode,Callback cb){connect(f,e,mode,"local",cb);}void connect(File f,AndroidStandardExitStore.Entry e,Callback cb){connect(f,e,"wg",cb);}void restoreCaptured(File f,AndroidStandardExitStore.Entry e,String mode,String execution,String selected,Callback cb){connect(f,e,mode,execution,cb);this.selected=selected;}
 String capturedTorExit(AndroidHomeStateStore.Snapshot s){return "8.8.4.4";}String capturedExternalExit(AndroidHomeStateStore.Snapshot s){return "8.8.4.4";}boolean disconnectAndDrainCaptured(String s){AndroidHomeStateStore.disconnected(NativeUsageBoundary.context);return true;}boolean disconnectCaptured(String s){return disconnectAndDrainCaptured(s);}void disconnect(){disconnectAndDrainCaptured("");}boolean isActiveOrTransitioning(){return false;}
}
final class AndroidNodeStatistics{static final class Record{double median,trimmedMean,p90;int samples;boolean eligible(){return false;}}static Record load(AndroidNodeStore.Node node){return null;}}
final class AndroidOpenVPN{static JSONObject endpoint(AndroidStandardExitStore.Entry e,String mode){throw new AssertionError("OpenVPN engine is outside this usage fixture");}static void validatePairing(AndroidStandardExitStore.Entry e){}static void validateResponseProbes(AndroidStandardExitStore.Entry e){}}
final class AndroidExternalAmnezia{static void endpoint(AndroidStandardExitStore.Entry e){}}
final class AndroidExternalProtection{static void validate(JSONObject p){}}
'''

ACTIVITY = r'''package com.eabusham.routervpn;
import java.util.*;import android.content.SharedPreferences;import android.os.Bundle;
final class UsageActivity extends android.app.Activity{
 final android.widget.TextView statusView=new android.widget.TextView(this);final android.widget.Button connectButton=new android.widget.Button(this);String toast="";
 final android.widget.Button nodeButton=new android.widget.Button(this),fastestButton=new android.widget.Button(this);
 // SHIPPING_MAP_CONSTANTS
 AndroidNodeStore nodeStore;AndroidStandardExitStore exitStore=new AndroidStandardExitStore(this);AndroidUnifiedNodeCatalog catalog;AndroidUnifiedConnectionController connection;RouterVpnNodeMapView mapView=new RouterVpnNodeMapView();UsageMapTelemetry telemetry=new UsageMapTelemetry();
 // SHIPPING_PREFS
 // The actual helper may observe this explicit unproved boundary, never accept it.
 static final class UnprovedExternalReceipt{String id;double medianMs=77;int checks;UnprovedExternalReceipt(String id){this.id=id;}void requireCurrent(){checks++;throw new IllegalStateException("usage fixture owns no live external measurement");}}
 UnprovedExternalReceipt currentExternalReceipt;
 // SHIPPING_EXTERNAL_LATENCY
 AndroidOrderedPathPresentation orderedPresentation;AndroidOrderedPathPresentation currentOrderedPresentation(){return orderedPresentation!=null&&orderedPresentation.current(this)?orderedPresentation:null;}
 boolean mutationBusy(){return AndroidVpnMutationGuard.isBusy(this);}void map(){refreshNodes();}SharedPreferences mapPreferences(){return prefs();}
 boolean isDestroyed(){return false;}void toast(String message){toast=message;}void refreshAll(){statusView.setText("Refreshed current Home");}void refreshConnectionLater(){}AndroidUnifiedConnectionController.Callback userCallback(){return callback();}
 // SHIPPING_CALLBACK
 // SHIPPING_MAP_PROJECTION
}
// Record Canvas primitives and delayed frame requests. The product's onDraw,
// path setters, projection and marker handling are compiled together.
class MapCanvasBoundary {
 static final class Paint {enum Align{LEFT,CENTER} int color;void setTextAlign(Align a){} void setColor(int value){color=value;}int getColor(){return color;}}
 static final class RectF {
  float left,top,right,bottom;
  RectF(float l,float t,float r,float b){left=l;top=t;right=r;bottom=b;}
  float width(){return right-left;}float height(){return bottom-top;}
  boolean contains(float x,float y){return x>=left&&x<right&&y>=top&&y<bottom;}
  float centerX(){return (left+right)/2;}float centerY(){return (top+bottom)/2;}
 }
 static final class MotionEvent {
  static final int ACTION_DOWN=0,ACTION_UP=1,ACTION_CANCEL=3,ACTION_POINTER_DOWN=5;
  final int action;final float x,y;
  MotionEvent(int action,float x,float y){this.action=action;this.x=x;this.y=y;}
  int getActionMasked(){return action;}float getX(){return x;}float getY(){return y;}
 }
 static final class AccessibilityNodeInfo {
  static final int ACTION_CLICK=16;
  record AccessibilityAction(int action,String label){}
  String clickLabel;
  void addAction(AccessibilityAction value){if(value.action()==ACTION_CLICK)clickLabel=value.label();}
 }
 static final class Manifest {static final class permission {static final String ACCESS_FINE_LOCATION="fine",ACCESS_COARSE_LOCATION="coarse";}}
 static final class Activity {int permissionPrompts;void requestPermissions(String[] which,int code){permissionPrompts++;}}
 final Activity activity=new Activity();Activity findActivity(){return activity;}
 static final int LOCATION_PERMISSION_REQUEST=6403;
 String description;void setContentDescription(String value){description=value;}
 public boolean onTouchEvent(MotionEvent e){return false;}public boolean performClick(){return false;}
 public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info){}public void onWindowFocusChanged(boolean focus){}
 static final class SystemClock {static long now=120_000_000_000L;static long elapsedRealtimeNanos(){return now;}}
 static final class Location {
  final long at;final double lat,lon;final float accuracy;
  Location(long at,double lat,double lon,float accuracy){this.at=at;this.lat=lat;this.lon=lon;this.accuracy=accuracy;}
  Location(Location other){this(other.at,other.lat,other.lon,other.accuracy);}
  long getElapsedRealtimeNanos(){return at;}double getLatitude(){return lat;}double getLongitude(){return lon;}
  float getAccuracy(){return accuracy;}boolean hasAccuracy(){return true;}
 }
 interface LocationListener {void onLocationChanged(Location l);void onProviderDisabled(String p);void onProviderEnabled(String p);void onStatusChanged(String p,int s,android.os.Bundle b);}
 static final class Looper {static Looper getMainLooper(){return null;}}
 static final class LocationManager {
  static final String GPS_PROVIDER="gps",NETWORK_PROVIDER="network";
  Location cached; LocationListener listener;
  List<String> getProviders(boolean enabled){return List.of(GPS_PROVIDER);}Location getLastKnownLocation(String provider){return cached;}
  void requestSingleUpdate(String p,LocationListener l,Looper loop){listener=l;}
  void removeUpdates(LocationListener l){if(listener==l)listener=null;}
 }
 static final long MAX_LAST_LOCATION_AGE_MS=30_000;static final float MAX_LOCATION_ACCURACY_METERS=10_000;
 final Paint background=new Paint(),oceanGlow=new Paint(),axis=new Paint(),grid=new Paint(),text=new Paint(),secondary=new Paint(),
  path=new Paint(),packet=new Paint(),entryPin=new Paint(),exitPin=new Paint(),hopPin=new Paint(),externalPin=new Paint(),
  selectedPin=new Paint(),normalPin=new Paint(),userPin=new Paint(),locationButton=new Paint();
 final class Canvas {
  int segments,packets,entries,exits,locateButtons,userPins,externalPins,landDraws;float longestX,packetX;
  final List<Integer> segmentColors=new ArrayList<>(),hopColors=new ArrayList<>();
  void drawRoundRect(RectF bounds,float x,float y,Paint p){if(p==locationButton)locateButtons++;}
  void drawOval(RectF bounds,Paint p){}
  void drawText(String text,float x,float y,Paint p){}
  void drawLine(float x,float y,float endX,float endY,Paint p){if(p==path){segments++;segmentColors.add(p.getColor());longestX=Math.max(longestX,Math.abs(endX-x));}}
  void drawCircle(float x,float y,float radius,Paint p){if(p==packet){packets++;packetX=x;}if(p==hopPin)hopColors.add(p.getColor());if(p==externalPin)externalPins++;if(p==entryPin)entries++;if(p==exitPin)exits++;if(p==userPin)userPins++;}
 }
 final class Land {void draw(Canvas canvas,RectF world){if(canvas.segments!=0||canvas.entries!=0||canvas.exits!=0)throw new AssertionError("Geography covered a route");canvas.landDraws++;}}
 final Land land=new Land();
 Location userLocation;String locationState="LOCATE ME";int nextFrames;
 boolean permission=true,locationRequestPending;final LocationManager locationManager=new LocationManager();LocationListener locationListener;
 Runnable delayed;long delay;
 void postDelayed(Runnable job,long ms){delayed=job;delay=ms;}void removeCallbacks(Runnable job){if(delayed==job)delayed=null;}
 boolean hasLocationPermission(){return permission;}protected void onDetachedFromWindow(){}
 protected void onDraw(Canvas c){} void invalidate(){} void postInvalidateDelayed(long ms){if(ms!=48)throw new AssertionError("frame cadence");nextFrames++;}
 int getWidth(){return 640;}int getHeight(){return 400;}float dp(float v){return v;}Paint halo(int color){return new Paint();}
}
final class RouterVpnNodeMapView extends MapCanvasBoundary {
 static final String ROLE_ENTRY="entry",ROLE_HOP="hop",ROLE_EXIT="exit",ROLE_SELECTED="selected",ROLE_EXTERNAL="external",ROLE_NORMAL="normal";
 boolean locationTouchStarted;
 interface OnMarkerClickListener{void onMarkerClick(Marker marker);}OnMarkerClickListener markerClickListener;
 void touch(int action,float x,float y){onTouchEvent(new MotionEvent(action,x,y));}
 String advertisedAction(){var info=new AccessibilityNodeInfo();onInitializeAccessibilityNodeInfo(info);return info.clickLabel;}
 // SHIPPING_MAP_MARKER
 // SHIPPING_MAP_VALID
 // SHIPPING_MAP_DRAW
 // SHIPPING_HOP_COLORS
 final Runnable locationExpiry=this::hideRealUserLocation;
 void requestFix(){requestFreshLocation();}void hideFix(){hideRealUserLocation();}
 List<Marker> markers=List.of();List<String> orderedPath=List.of();boolean orderedLive;java.util.function.BooleanSupplier frameOwner;
 Canvas frame(){nextFrames=0;Canvas canvas=new Canvas();onDraw(canvas);return canvas;}
 boolean renders(Marker marker){return valid(marker);}
}
final class UsageMapTelemetry {double cachedMedian(String id){return 0;}}
'''

_map_source = (JAVA / 'RouterVpnNodeMapView.java').read_text()
_map_methods = ('    void setMarkers(', '    void setOrderedPath(', '    @Override protected void onDraw(',
                '    private void drawLocationButton(', '    private RectF locationButtonRect(', '    private RectF worldRect(',
                '    private boolean freshLocation(', '    private void requestFreshLocation(', '    private void acceptRealLocation(',
                '    private void hideRealUserLocation(', '    @Override protected void onDetachedFromWindow(',
                '    private void enableRealUserLocation(', '    private void refreshLocationControl(',
                '    @Override public void onInitializeAccessibilityNodeInfo(', '    @Override public boolean performClick(',
                '    @Override public boolean onTouchEvent(', '    @Override public void onWindowFocusChanged(',
                '    private void drawRouteSegment(', '    private int routeColor(',
                '    private boolean validUserLocation(', '    private Paint paintFor(', '    private float xFor(', '    private float yFor(')
ACTIVITY = ACTIVITY.replace(' // SHIPPING_MAP_DRAW', '\n'.join(S.block(_map_source, method) for method in _map_methods))
ACTIVITY = ACTIVITY.replace(' // SHIPPING_HOP_COLORS', next(line for line in _map_source.splitlines() if 'int[] HOP_COLORS=' in line))

EXTERNAL_ACTIVITY = r'''package com.eabusham.routervpn;
import android.app.Activity;import android.app.AlertDialog;import android.content.Intent;import android.net.VpnService;import android.os.Bundle;import android.widget.*;import java.util.*;import java.nio.charset.StandardCharsets;import org.json.*;
// Exact request, permission, recreation, owner and completion methods. Forms
// and native engine proof remain the separately exercised UI/runtime boundary.
final class StandardExitActivity extends Activity{
 // SHIPPING_FIELDS
 String lastToast="";int selections;
 StandardExitActivity(Bundle state){nodeStore=new AndroidNodeStore(this);exitStore=new AndroidStandardExitStore(this);runtime=AndroidRuntimeRegistry.get(this).standardExit;statusView=new TextView(this);restorePending(state);}
 void direct(AndroidStandardExitStore.Entry e){requestDirect(e);}void router(AndroidNodeStore.Node n,AndroidStandardExitStore.Entry e){requestConnect(n,e,"wg","auto");}void ordinary(AndroidStandardExitStore.Entry n,AndroidStandardExitStore.Entry e){requestOrdinaryTor(n,e);}
 void rememberExternalPath(AndroidNodeStore.Node n,AndroidStandardExitStore.Entry e,String mode){selections++;}void refresh(){statusView.setText("Refreshed current external state");}void toast(String message){lastToast=message;}static String safe(Throwable t){return t.getMessage();}
 // SHIPPING_METHODS
}
final class AndroidDNSMeasurementDialog{void close(){}}
'''

HARNESS = r'''package com.eabusham.routervpn;
import android.content.*;import android.os.Bundle;import java.io.*;import java.nio.file.*;import java.util.*;import java.util.concurrent.*;import java.util.concurrent.atomic.*;import org.json.*;
public final class NodeUsageTest{
 static int checks;static void check(boolean ok,String message){checks++;if(!ok)throw new AssertionError(message);}
 static void await(CountDownLatch latch,String message)throws Exception{check(latch.await(4,TimeUnit.SECONDS),message);}
 static void importedCaptureBoundary()throws Exception{
  boolean nativeRefused=false;try{io.nekohasekai.libbox.Libbox.routerNodeChainImportedOpenVPNMemberInput("","");}catch(AssertionError expected){nativeRefused="Usage fixture cannot compile a native OpenVPN member.".equals(expected.getMessage());}check(nativeRefused,"usage fixture fabricated a native OpenVPN member");
  AndroidExternalPolicy.importedCaptureCalls=0;AndroidExternalPolicy.refusedImportedCapture=null;
  for(String kind:List.of("null","unsupported")){
   AndroidStandardExitStore.Entry entry=null;if(kind.equals("unsupported")){entry=new AndroidStandardExitStore.Entry();entry.protocol="tor";}
   boolean refused=false;try{AndroidExternalPolicy.captureImportedEntry(entry);}catch(IllegalArgumentException expected){refused=true;}
   check(refused&&AndroidExternalPolicy.importedCaptureCalls==0,"usage imported capture admitted malformed source: "+kind);
  }
  AndroidStandardExitStore.Entry entry=new AndroidStandardExitStore.Entry();entry.id="original-openvpn";entry.name="Original OpenVPN";entry.protocol="openvpn";entry.openVPNConfig="client\nproto udp\nremote 192.0.2.44 1194\n";
  String original=AndroidStandardExitStore.snapshot(entry);boolean refused=false;
  try{AndroidExternalPolicy.captureImportedEntry(entry);}catch(AssertionError expected){refused="Usage fixture has no native imported capture authority.".equals(expected.getMessage());}
  check(refused&&AndroidExternalPolicy.importedCaptureCalls==1,"usage fixture fabricated native imported capture authority");
  check(AndroidExternalPolicy.refusedImportedCapture!=entry&&original.equals(AndroidStandardExitStore.snapshot(AndroidExternalPolicy.refusedImportedCapture)),"usage imported capture omitted its original defensive source copy");
  entry.openVPNConfig="changed source";check(original.equals(AndroidStandardExitStore.snapshot(AndroidExternalPolicy.refusedImportedCapture)),"usage imported capture followed replacement source");
 }
 static void savedPolicyValidation()throws Exception{
  AndroidStandardExitStore.Entry e=new AndroidStandardExitStore.Entry();e.id="hostname-policy";e.name="Original imported middle";e.protocol="shadowsocks";e.server="Middle.Example";e.serverPort=8388;e.expectedPublicIp="198.51.100.31";e.method="2022-blake3-aes-128-gcm";e.secret=java.util.Base64.getEncoder().encodeToString(new byte[16]);
  JSONObject original=new JSONObject().put("dns_mode","custom").put("dns_protocol","tcp").put("dns_host","192.0.2.53").put("dns_port",53).put("kill_switch",true).put("kill_switch_policy","always");e.policy=original;AndroidStandardExitStore.validate(e);check(e.server.equals("Middle.Example")&&e.policy==original,"saved hostname validation changed its original source");
  for(String fault:List.of("unknown-field","protection-type","dns-port-type","text-bound")){
   e.policy=new JSONObject(original.toString());if(fault.equals("unknown-field"))e.policy.put("borrowed_policy",true);else if(fault.equals("protection-type"))e.policy.put("kill_switch","true");else if(fault.equals("dns-port-type"))e.policy.put("dns_port","53");else e.policy.put("dns_path","x".repeat(4097));
   boolean refused=false;try{AndroidStandardExitStore.validate(e);}catch(Exception expected){refused=true;}check(refused,"saved hostname policy accepted malformed "+fault);
  }
 }
 static final class Callback implements AndroidUnifiedConnectionController.Callback{
  final AndroidUnifiedConnectionController.Callback delegate;final boolean user;boolean ok;int completions;String message="";
  Callback(UsageActivity a,boolean user){delegate=a.userCallback();this.user=user;}public boolean recordsNodeUsage(){return user&&delegate.recordsNodeUsage();}public void progress(String s){delegate.progress(s);}public void owned(String s){delegate.owned(s);}public void finished(boolean success,String s){ok=success;message=s;completions++;delegate.finished(success,s);}
 }
 static JSONObject bundle(String proof,String name,int count)throws Exception{return new JSONObject().put("profileSchemaVersion",4).put("nodeProofId",proof).put("profiles",new JSONObject().put("wg",new JSONObject().put("fixture","engine-boundary"))).put("modes",new JSONArray().put(new JSONObject().put("id","wg"))).put("activeRouterProfileId","home").put("routerProfiles",new JSONArray().put(new JSONObject().put("id","home").put("name",name).put("node_proof_id",proof).put("endpoint","192.0.2.10").put("router_api","https://192.0.2.10:8443").put("api_token","private-api-token").put("use_count",count).put("last_used_at","2025-01-01T00:00:00Z").put("dns","home").put("mtu",1280)));}
 static final class Fixture implements AutoCloseable{
  final UsageActivity activity;final AndroidNodeStore store;final AndroidStandardExitStore exits;final AndroidUnifiedNodeCatalog catalog;final AndroidNodeStore.Node a,b;final AndroidStandardExitStore.Entry x,y;AndroidUnifiedConnectionController controller;Callback callback;
  Fixture(Path root)throws Exception{Context.preferences.clear();Context.nextFiles=Files.createTempDirectory(root,"usage-").toFile();activity=new UsageActivity();NativeUsageBoundary.reset(activity);AndroidVpnMutationGuard.busy=false;AndroidRuntimeRegistry.instance=new AndroidRuntimeRegistry();android.net.VpnService.needsPermission=false;store=new AndroidNodeStore(activity);exits=new AndroidStandardExitStore(activity);catalog=new AndroidUnifiedNodeCatalog(store,exits);a=store.importBundle(bundle("a".repeat(64),"Alpha",5).toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));b=store.importBundle(bundle("b".repeat(64),"Beta",1).toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));store.select(a.id);x=external("provider-x","shadowsocks");y=external("provider-y","tor");exits.save(x);exits.save(y);controller=new AndroidUnifiedConnectionController(activity,store);activity.nodeStore=store;activity.catalog=catalog;activity.connection=controller;callback=new Callback(activity,true);}
  AndroidStandardExitStore.Entry external(String id,String protocol)throws Exception{AndroidStandardExitStore.Entry e=new AndroidStandardExitStore.Entry();e.id=id;e.name=id;e.protocol=protocol;e.server="8.8.8.8";e.serverPort=443;e.method="aes-256-gcm";e.secret="private-external-secret";e.tlsServerName="imported.example.test";e.expectedPublicIp="8.8.4.4";e.responseProbe=new JSONObject().put("url","https://8.8.8.8/response");if(AndroidTorProfile.isTor(protocol))e.responseProbe=new JSONObject();return e;}
  File usage(){return store.usageFile();}byte[] read(File f)throws Exception{return Files.readAllBytes(f.toPath());}void idle(){AndroidHomeStateStore.disconnected(activity);callback=new Callback(activity,true);NativeUsageBoundary.beforeFinish=null;NativeUsageBoundary.fault="";NativeUsageBoundary.fail=false;NativeUsageBoundary.omitOwned=false;}
  int count(String kind,String id)throws Exception{if(!usage().exists())return 0;JSONArray rows=new JSONObject(Files.readString(usage().toPath())).getJSONArray("records");for(int i=0;i<rows.length();i++){JSONObject r=rows.getJSONObject(i);if(kind.equals(r.getString("kind"))&&id.equals(r.getString("node_id")))return r.getInt("count");}return 0;}
  JSONObject row(String id)throws Exception{JSONArray rows=new JSONObject(Files.readString(usage().toPath())).getJSONArray("records");for(int i=0;i<rows.length();i++)if(id.equals(rows.getJSONObject(i).getString("node_id")))return rows.getJSONObject(i);throw new AssertionError("missing usage row");}
  void connect(){controller.connect("wg",List.of(),callback);}void finish(){NativeUsageBoundary.finish();}public void close(){controller.close();AndroidHomeStateStore.disconnected(activity);}
 }
 static void ordinary(Path root)throws Exception{
  try(Fixture f=new Fixture(root)){byte[] source=f.read(f.a.file),active=f.read(new File(f.activity.getFilesDir(),AndroidNodeStore.ACTIVE_BUNDLE));f.connect();check(!f.usage().exists(),"launch or progress counted before proof");f.finish();check(f.callback.ok&&f.count("router-vpn",f.a.id)==6,"successful shipping user connection did not increment imported baseline");check(Arrays.equals(source,f.read(f.a.file))&&Arrays.equals(active,f.read(new File(f.activity.getFilesDir(),AndroidNodeStore.ACTIVE_BUNDLE))),"usage mutated private Router bundle");byte[] receipt=f.read(f.usage());NativeUsageBoundary.last.run();check(Arrays.equals(receipt,f.read(f.usage())),"duplicate native callback incremented usage");check(new AndroidUnifiedNodeCatalog(new AndroidNodeStore(f.activity),new AndroidStandardExitStore(f.activity)).list(AndroidUnifiedNodeCatalog.SORT_MOST_USED).get(0).useCount==6,"fresh catalog did not merge durable sidecar");check(!Files.readString(f.usage().toPath()).contains("private-api-token"),"usage stored Router secret");f.idle();f.connect();f.finish();check(f.count("router-vpn",f.a.id)==7,"imported count was repeatedly added instead of maximum");}
  for(String shape:List.of("custom","multi","external","direct","ordinary","imported"))try(Fixture f=new Fixture(root)){
   if(shape.equals("custom"))f.controller.connectNode(f.b,"custom:Saved",List.of("wg","shadowsocks"),f.callback);
   else if(shape.equals("multi"))f.controller.connectMultihop(f.a,f.b,"shadowsocks","auto","wg",f.callback);
   else if(shape.equals("external"))f.controller.connectExternal(f.a,f.x,false,"wg","auto",f.callback);
   else if(shape.equals("direct"))f.controller.connectExternal(null,f.x,true,"wg","local",f.callback);
   else if(shape.equals("imported"))f.controller.connectImportedMultihop(f.x,f.b,"shadowsocks","local",f.callback);
   else f.controller.connectOrdinaryTor(f.x,f.y,"local",f.callback);
   check(!f.usage().exists(),"candidate/trial counted before final proof: "+shape);f.finish();check(f.callback.ok&&!f.callback.message.contains("could not be saved"),"shipping usage failed: "+shape+" "+f.callback.message);
   if(shape.equals("custom"))check(f.count("router-vpn",f.b.id)==2&&f.count("router-vpn",f.a.id)==0,"CUSTOM used selected rather than requested node");
   if(shape.equals("multi"))check(f.count("router-vpn",f.a.id)==6&&f.count("router-vpn",f.b.id)==2,"final multihop did not count both distinct nodes once");
   if(shape.equals("external"))check(f.count("router-vpn",f.a.id)==6&&f.count("external",f.x.id)==1,"final external graph did not count both nodes");
   if(shape.equals("direct"))check(f.count("router-vpn",f.a.id)==0&&f.count("external",f.x.id)==1,"direct external inherited unrelated Router usage");
   if(shape.equals("ordinary"))check(f.count("external",f.x.id)==1&&f.count("external",f.y.id)==1,"ordinary Tor graph did not count distinct external nodes");
   if(shape.equals("imported"))check(f.count("external",f.x.id)==1&&f.count("router-vpn",f.b.id)==2&&f.count("router-vpn",f.a.id)==0,"imported multihop did not count both original typed nodes");
   check(!Files.readString(f.usage().toPath()).contains("private-external-secret"),"usage stored external secret");
  }
 }
 static void excluded(Path root)throws Exception{
  for(String fault:List.of("failed","owner","proof","emergency","generation","path","omit-owned","source","source-key","exit-source","denied","cancelled"))try(Fixture f=new Fixture(root)){
   if(fault.equals("failed"))NativeUsageBoundary.fail=true;else if(fault.equals("omit-owned"))NativeUsageBoundary.omitOwned=true;else NativeUsageBoundary.fault=fault;
   if(fault.equals("source")||fault.equals("source-key"))NativeUsageBoundary.beforeFinish=()->{try{byte[] value=f.read(f.a.file);if(fault.equals("source"))value=(new String(value,java.nio.charset.StandardCharsets.UTF_8)+" ").getBytes(java.nio.charset.StandardCharsets.UTF_8);else{JSONObject b=new JSONObject(new String(value,java.nio.charset.StandardCharsets.UTF_8));AndroidProfileSelection.selectedRouterProfile(b).put("api_token","replacement");value=b.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);}AndroidPrivateFileStore.write(f.a.file,value,AndroidNodeStore.MAX_BUNDLE);}catch(Exception e){throw new AssertionError(e);}};
   if(fault.equals("exit-source"))NativeUsageBoundary.beforeFinish=()->{try{File p=new File(f.activity.getFilesDir(),"standard-exits.json");AndroidPrivateFileStore.write(p,(Files.readString(p.toPath())+" ").getBytes(java.nio.charset.StandardCharsets.UTF_8),512*1024);}catch(Exception e){throw new AssertionError(e);}};
   if(fault.equals("denied")||fault.equals("cancelled"))android.net.VpnService.needsPermission=true;
   if(fault.equals("exit-source"))f.controller.connectExternal(f.a,f.x,false,"wg","local",f.callback);else f.connect();
   if(fault.equals("denied"))f.controller.onActivityResult(f.activity.permissionRequest,0);else if(fault.equals("cancelled"))f.controller.cancelPermissionPending();else f.finish();
   check(!f.usage().exists(),"invalid adoption recorded usage: "+fault);
  }
  for(String shape:List.of("router","node","multi","external"))try(Fixture f=new Fixture(root)){Callback temporary=new Callback(f.activity,false);if(shape.equals("router"))f.controller.connect("smart-auto",List.of(),temporary);if(shape.equals("node"))f.controller.connectNode(f.b,"wg",List.of(),temporary);if(shape.equals("multi"))f.controller.connectMultihop(f.a,f.b,"shadowsocks","auto","wg",temporary);if(shape.equals("external"))f.controller.connectExternal(f.a,f.x,false,"wg","auto",temporary);f.finish();check(temporary.ok&&!f.usage().exists(),"temporary trial counted as user adoption: "+shape);}
  try(Fixture f=new Fixture(root)){AndroidStartupPolicy.Attempt startup=new AndroidStartupPolicy.Attempt();startup.node=f.a;startup.mode="smart-auto";f.controller.connectStartup(startup,f.callback);f.finish();check(f.callback.ok&&!f.usage().exists(),"automatic startup counted as user adoption");}
  try(Fixture f=new Fixture(root)){f.connect();f.finish();byte[] prior=f.read(f.usage());AndroidUnifiedConnectionController.RestorePoint point=f.controller.captureRestorePoint();f.idle();AndroidHomeStateStore.Snapshot idle=f.controller.captureIdle();f.controller.restoreCaptured(point,idle,f.callback);f.finish();check(f.callback.ok&&Arrays.equals(prior,f.read(f.usage())),"proved temporary restoration counted another use");}
  try(Fixture f=new Fixture(root)){android.net.VpnService.needsPermission=true;Callback temporary=new Callback(f.activity,false);f.controller.connect("wg",List.of(),temporary);Bundle state=new Bundle();f.controller.savePending(state);int code=f.activity.permissionRequest;f.controller.close();f.controller=new AndroidUnifiedConnectionController(f.activity,f.store);f.controller.restorePending(state,f.callback);f.controller.onActivityResult(code,android.app.Activity.RESULT_OK);f.finish();check(f.callback.ok&&!f.usage().exists(),"Activity recreation promoted temporary receipt into user usage");}
  try(Fixture f=new Fixture(root)){android.net.VpnService.needsPermission=true;f.connect();Bundle state=new Bundle();f.controller.savePending(state);int code=f.activity.permissionRequest;f.controller.close();f.controller=new AndroidUnifiedConnectionController(f.activity,f.store);Callback temporary=new Callback(f.activity,false);f.controller.restorePending(state,temporary);f.controller.onActivityResult(code,android.app.Activity.RESULT_OK);f.finish();check(temporary.ok&&f.count("router-vpn",f.a.id)==6,"Activity recreation lost original user usage intent");}
 }
 static void packetFields(AndroidStandardExitStore.Entry e)throws Exception{
  if(!List.of("wireguard","amneziawg").contains(e.protocol))return;
  e.wgPrivateKey=java.util.Base64.getEncoder().encodeToString("x".repeat(32).getBytes(java.nio.charset.StandardCharsets.UTF_8));e.wgPeerPublicKey=java.util.Base64.getEncoder().encodeToString("p".repeat(32).getBytes(java.nio.charset.StandardCharsets.UTF_8));
  e.wgPreSharedKey=java.util.Base64.getEncoder().encodeToString("k".repeat(32).getBytes(java.nio.charset.StandardCharsets.UTF_8));e.wgMtu=1360;e.wgKeepalive=25;e.wgAddresses.addAll(List.of("10.93.0.2/32","fd93::2/128"));e.wgAllowedIps.addAll(List.of("0.0.0.0/0","::/0"));
  if(e.protocol.equals("amneziawg"))e.awgParameters=new JSONObject().put("jc","3").put("jmin","40").put("jmax","900").put("s1","15").put("s2","16").put("s3","32").put("s4","32").put("h1","100-110").put("h2","200-210").put("h3","300-310").put("h4","400-410");
 }
 static List<String> importedProtocols=List.of("shadowsocks","hysteria2");
 static void importedExclusions(Path root)throws Exception{for(String protocol:importedProtocols)for(String finalMode:(importedProtocols.contains("socks5")?List.of("shadowsocks","hysteria2","wg","awg2-fast","awg2-strong"):List.of("shadowsocks","hysteria2"))){
  try(Fixture f=new Fixture(root)){
   var imported=AndroidStandardExitStore.copy(f.x);imported.id=f.a.id;imported.protocol=protocol;packetFields(imported);f.exits.save(imported);
   f.controller.connectImportedMultihop(imported,f.b,finalMode,"local",f.callback);check(NativeUsageBoundary.pending!=null,"imported usage launch failed "+protocol+"/"+finalMode+": "+f.callback.message);f.finish();
   check(f.callback.ok&&f.count("external",f.a.id)==1&&f.count("router-vpn",f.a.id)==0&&f.count("router-vpn",f.b.id)==2,"imported usage conflated same text IDs across original node kinds: "+protocol);
   byte[] receipt=f.read(f.usage());NativeUsageBoundary.last.run();check(Arrays.equals(receipt,f.read(f.usage())),"duplicate imported completion counted both nodes again");
  }
  for(String fault:List.of("failed","owner","omit-owned","entry-source","final-source","cancelled","temporary"))try(Fixture f=new Fixture(root)){
   f.x.protocol=protocol;packetFields(f.x);f.exits.save(f.x);
   if(fault.equals("failed"))NativeUsageBoundary.fail=true;
   if(fault.equals("owner"))NativeUsageBoundary.fault="owner";
   if(fault.equals("omit-owned"))NativeUsageBoundary.omitOwned=true;
   if(fault.equals("entry-source"))NativeUsageBoundary.beforeFinish=()->{try{File original=new File(f.activity.getFilesDir(),"standard-exits.json");AndroidPrivateFileStore.write(original,(Files.readString(original.toPath())+" ").getBytes(java.nio.charset.StandardCharsets.UTF_8),512*1024);}catch(Exception e){throw new AssertionError(e);}};
   if(fault.equals("final-source"))NativeUsageBoundary.beforeFinish=()->{try{AndroidPrivateFileStore.write(f.b.file,(Files.readString(f.b.file.toPath())+" ").getBytes(java.nio.charset.StandardCharsets.UTF_8),AndroidNodeStore.MAX_BUNDLE);}catch(Exception e){throw new AssertionError(e);}};
   if(fault.equals("cancelled"))android.net.VpnService.needsPermission=true;
   Callback callback=fault.equals("temporary")?new Callback(f.activity,false):f.callback;
   f.controller.connectImportedMultihop(f.x,f.b,finalMode,"local",callback);
   if(fault.equals("cancelled"))f.controller.cancelPermissionPending();else f.finish();
   check(!f.usage().exists(),"unproved or replaced imported graph recorded usage: "+fault);
  }
 }}
 static void stableIdentity(Path root)throws Exception{
  for(String change:List.of("name","dns","mtu","client-key","endpoint","api-token"))try(Fixture f=new Fixture(root)){f.connect();f.finish();f.idle();JSONObject b=new JSONObject(Files.readString(f.a.file.toPath()));JSONObject p=AndroidProfileSelection.selectedRouterProfile(b);if(change.equals("client-key"))b.getJSONObject("profiles").getJSONObject("wg").put("wg.conf",android.util.Base64.encodeToString("[Interface]\nPrivateKey = changed-client\n".getBytes(java.nio.charset.StandardCharsets.UTF_8),0));else p.put(change.equals("api-token")?"api_token":change,change.equals("mtu")?1376:"changed-"+change);AndroidPrivateFileStore.write(f.a.file,b.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8),AndroidNodeStore.MAX_BUNDLE);f.connect();f.finish();check(f.callback.ok&&f.count("router-vpn",f.a.id)==(change.equals("api-token")?6:7),"stable Router identity mixed or reset usage: "+change);}
  for(String change:List.of("name","policy","location","credential","server"))try(Fixture f=new Fixture(root)){f.controller.connectExternal(null,f.x,true,"wg",f.callback);f.finish();f.idle();AndroidStandardExitStore.Entry e=f.exits.get(f.x.id);if(change.equals("name"))e.name="renamed";if(change.equals("policy"))e.policy=new JSONObject().put("mtu",1376).put("dns","selected");if(change.equals("location")){e.location="Chicago";e.latitude=41.8781;e.longitude= -87.6298;}if(change.equals("credential"))e.secret="replacement-private-secret";if(change.equals("server"))e.server="8.8.4.4";e.responseProbe=new JSONObject();f.exits.save(e);f.controller.connectExternal(null,e,true,"wg",f.callback);f.finish();check(f.callback.ok&&f.count("external",e.id)==(change.equals("credential")||change.equals("server")?1:2),"stable external identity mixed or reset usage: "+change);}
 }
 static void failedStore(Path root)throws Exception{
  for(String corrupt:List.of("duplicate-schema","duplicate-id","unknown-field","fractional-count","wrong-kind","oversize","directory"))try(Fixture f=new Fixture(root)){
   f.connect();f.finish();f.idle();String original=Files.readString(f.usage().toPath());JSONObject rootValue=new JSONObject(original);JSONArray rows=rootValue.getJSONArray("records");
   if(corrupt.equals("duplicate-schema"))Files.writeString(f.usage().toPath(),original.replace("\"schema\":1","\"schema\":1,\"schema\":1"));
   if(corrupt.equals("duplicate-id")){rows.put(new JSONObject(rows.getJSONObject(0).toString()));Files.writeString(f.usage().toPath(),rootValue.toString());}
   if(corrupt.equals("unknown-field")){rootValue.put("token","unexpected");Files.writeString(f.usage().toPath(),rootValue.toString());}
   if(corrupt.equals("fractional-count")){rows.getJSONObject(0).put("count",6.5);Files.writeString(f.usage().toPath(),rootValue.toString());}
   if(corrupt.equals("wrong-kind")){rows.getJSONObject(0).put("kind","borrowed");Files.writeString(f.usage().toPath(),rootValue.toString());}
   if(corrupt.equals("oversize"))Files.writeString(f.usage().toPath()," ".repeat(96*1024+1));
   if(corrupt.equals("directory")){Files.delete(f.usage().toPath());Files.createDirectory(f.usage().toPath());}
   byte[] before=f.usage().isFile()?f.read(f.usage()):null;f.connect();f.finish();check(f.callback.ok&&f.callback.message.contains("usage could not be saved"),"statistics failure corrupted success or was hidden: "+corrupt);check(f.activity.toast.contains("Node usage could not be saved"),"shipping state refresh hid usage-save warning: "+corrupt);check(AndroidHomeStateStore.snapshot(f.activity).connected,"usage failure disconnected proved tunnel");check(before==null?f.usage().isDirectory():Arrays.equals(before,f.read(f.usage())),"usage failure overwrote corrupt store: "+corrupt);AndroidUnifiedNodeCatalog.Item item=f.catalog.list(AndroidUnifiedNodeCatalog.SORT_MOST_USED).stream().filter(x->x.id.equals(f.a.id)).findFirst().orElseThrow();check(!item.usageAvailable&&item.subtitle().contains("usage unavailable"),"corrupt sidecar projected fabricated usage: "+corrupt);
  }
 }
 static void atomicOwner(Path root)throws Exception{
  try(Fixture f=new Fixture(root)){f.connect();CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1),sourceDone=new CountDownLatch(1),homeDone=new CountDownLatch(1);android.system.Os.holdTarget=f.usage().getAbsolutePath();android.system.Os.renameEntered=entered;android.system.Os.renameRelease=release;AtomicReference<Throwable> error=new AtomicReference<>();Thread finish=new Thread(()->{try{f.finish();}catch(Throwable e){error.set(e);}});finish.start();await(entered,"usage write did not reach actual atomic rename");byte[] original=f.read(f.a.file);Thread writer=new Thread(()->{try{AndroidPrivateFileStore.write(f.a.file,(new String(original,java.nio.charset.StandardCharsets.UTF_8)+" ").getBytes(java.nio.charset.StandardCharsets.UTF_8),AndroidNodeStore.MAX_BUNDLE);}catch(Throwable e){error.set(e);}finally{sourceDone.countDown();}});Thread owner=new Thread(()->{try{AndroidHomeStateStore.disconnected(f.activity);}catch(Throwable e){error.set(e);}finally{homeDone.countDown();}});writer.start();owner.start();try{check(!sourceDone.await(120,TimeUnit.MILLISECONDS)&&!homeDone.await(120,TimeUnit.MILLISECONDS),"source or Home owner changed inside usage check/write transaction");}finally{release.countDown();android.system.Os.holdTarget="";}finish.join(4000);writer.join(4000);owner.join(4000);check(!finish.isAlive()&&!writer.isAlive()&&!owner.isAlive()&&error.get()==null,"usage adoption blocked or leaked transaction threads: "+error.get());check(f.count("router-vpn",f.a.id)==6,"atomic completed adoption did not persist exactly once");check(!Arrays.equals(original,f.read(f.a.file))&&!AndroidHomeStateStore.snapshot(f.activity).connected,"serialized replacement did not complete after adoption");}
 }
 static void ranking(Path root)throws Exception{
  try(Fixture f=new Fixture(root)){f.connect();f.finish();f.idle();f.controller.connectNode(f.b,"wg",List.of(),f.callback);f.finish();List<AndroidUnifiedNodeCatalog.Item> items=f.catalog.list(AndroidUnifiedNodeCatalog.SORT_MOST_USED);check(items.get(0).id.equals(f.a.id)&&items.get(0).useCount==6,"Most used did not sort by durable count descending");check(f.catalog.list(AndroidUnifiedNodeCatalog.SORT_LAST_USED).get(0).id.equals(f.b.id),"Last used order was replaced by Most used");check(f.catalog.list(AndroidUnifiedNodeCatalog.SORT_NAME).get(0).name.equals("Alpha"),"existing Name order changed");JSONObject data=new JSONObject(Files.readString(f.usage().toPath()));JSONArray rows=data.getJSONArray("records");long second=(System.currentTimeMillis()/1000-10)*1000;for(int i=0;i<rows.length();i++){JSONObject r=rows.getJSONObject(i);r.put("count",10).put("used_at_ms",r.getString("node_id").equals(f.a.id)?second:second+100);}AndroidPrivateFileStore.write(f.usage(),data.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8),96*1024);check(f.catalog.list(AndroidUnifiedNodeCatalog.SORT_MOST_USED).get(0).id.equals(f.b.id),"Most used tie compared variable timestamp strings incorrectly");}
 }
 static void externalActivity(Path root)throws Exception{
  for(String shape:List.of("direct","router","ordinary"))for(boolean rotate:new boolean[]{false,true})try(Fixture f=new Fixture(root)){
   android.net.VpnService.needsPermission=true;StandardExitActivity first=new StandardExitActivity(null);if(shape.equals("direct"))first.direct(f.x);else if(shape.equals("router"))first.router(f.a,f.x);else first.ordinary(f.x,f.y);
   check(!f.usage().exists()&&NativeUsageBoundary.pending==null,"management screen counted before permission");Bundle state=new Bundle();first.onSaveInstanceState(state);String nonce=state.getString("pending_usage_permission","");check(nonce.matches("[0-9a-f]{32}")&&!state.values.toString().contains("private-"),"management usage state exposed sources or lacked receipt");
   StandardExitActivity current=first;if(rotate){current=new StandardExitActivity(state);first.onActivityResult(2101,android.app.Activity.RESULT_OK,null);check(NativeUsageBoundary.pending==null,"old recreated Activity consumed transferred permission");first.onDestroy();}
   current.onActivityResult(2101,android.app.Activity.RESULT_OK,null);check(!f.usage().exists()&&NativeUsageBoundary.pending!=null,"management usage counted without final proof");f.finish();check(f.count("external",f.x.id)==1,"management final node use missing: "+shape+"/"+rotate);if(shape.equals("router"))check(f.count("router-vpn",f.a.id)==6,"management Router entry use missing");if(shape.equals("ordinary"))check(f.count("external",f.y.id)==1,"management ordinary path did not count distinct final nodes");byte[] saved=f.read(f.usage());NativeUsageBoundary.last.run();check(Arrays.equals(saved,f.read(f.usage())),"management duplicate native callback counted twice");current.onActivityResult(2101,android.app.Activity.RESULT_OK,null);check(NativeUsageBoundary.pending==null,"management consumed permission replay started runtime");current.onDestroy();
  }
  for(String fault:List.of("failed","owner","generation","source","cancelled","destroyed","missing-process-owner","wrong-nonce","wrong-request","selection-only"))try(Fixture f=new Fixture(root)){
   android.net.VpnService.needsPermission=true;StandardExitActivity first=new StandardExitActivity(null);if(fault.equals("selection-only"))first.intent.putExtra("routervpn.select_external_path",true);first.router(f.a,f.x);
   if(fault.equals("selection-only")){check(NativeUsageBoundary.pending==null&&first.isFinishing(),"selection-only manager started runtime");Bundle saved=new Bundle();first.onSaveInstanceState(saved);check(saved.getString("pending_usage_permission","").isEmpty(),"selection-only manager minted usage intent");continue;}
   Bundle state=new Bundle();first.onSaveInstanceState(state);
   if(fault.equals("cancelled"))first.onActivityResult(2101,0,null);
   if(fault.equals("destroyed")||fault.equals("missing-process-owner")){first.finished=true;first.onDestroy();first.onActivityResult(2101,android.app.Activity.RESULT_OK,null);check(NativeUsageBoundary.pending==null,"destroyed management Activity launched its old permission");}
   if(fault.equals("wrong-nonce"))state.putString("pending_usage_permission","0".repeat(32));
   if(fault.equals("wrong-request"))state.putString("pending_request_digest","0".repeat(64));
   boolean rejected=Set.of("cancelled","destroyed","missing-process-owner","wrong-nonce","wrong-request").contains(fault);
   StandardExitActivity current=new StandardExitActivity(state);current.onActivityResult(2101,android.app.Activity.RESULT_OK,null);
   if(rejected){check(NativeUsageBoundary.pending==null&&!f.usage().exists(),"cancelled/recreated management receipt was replayed: "+fault);first.onDestroy();current.onDestroy();continue;}
   if(fault.equals("failed"))NativeUsageBoundary.fail=true;else if(fault.equals("source"))NativeUsageBoundary.beforeFinish=()->{try{AndroidPrivateFileStore.write(f.a.file,(Files.readString(f.a.file.toPath())+" ").getBytes(java.nio.charset.StandardCharsets.UTF_8),AndroidNodeStore.MAX_BUNDLE);}catch(Exception e){throw new AssertionError(e);}};else NativeUsageBoundary.fault=fault;
   f.finish();check(!f.usage().exists(),"management invalid final adoption counted: "+fault);if(!fault.equals("failed"))check(current.lastToast.contains("Node usage could not be saved"),"management refresh hid usage failure");current.onDestroy();first.onDestroy();
  }
 }
 static void externalMap(Path root)throws Exception{
  try(Fixture f=new Fixture(root)){
   f.activity.map();check(f.activity.mapView.markers.isEmpty(),"external node acquired a fabricated coordinate before metadata was saved");
   check(!f.activity.mapView.renders(new RouterVpnNodeMapView.Marker("legacy","Legacy",0,0,"normal",0)),"legacy Router placeholder became a false map pin");
   AndroidStandardExitStore.Entry e=f.exits.get(f.x.id);String old=AndroidStandardExitStore.snapshot(e);e.location="Chicago";e.latitude=41.8781;e.longitude= -87.6298;f.exits.saveIfUnchanged(e,old);
   AndroidUnifiedNodeCatalog.Item item=f.catalog.list().stream().filter(i->i.kind.equals("external")&&i.id.equals(e.id)).findFirst().orElseThrow();check(item.hasCoordinates()&&item.latitude==41.8781&&item.longitude== -87.6298&&item.location.equals("Chicago")&&item.subtitle().contains("Chicago")&&!item.hasMeasuredLatency(),"external catalog lost explicit coordinates/location or invented latency");
   f.activity.mapPreferences().edit().putString("selected_kind","external").putString("selected_id",e.id).apply();f.activity.map();check(f.activity.mapView.markers.size()==1,"shipping map omitted the external pin or created an absent pin");RouterVpnNodeMapView.Marker marker=f.activity.mapView.markers.get(0);check(marker.id.equals("external:"+e.id)&&marker.latitude==e.latitude&&marker.longitude==e.longitude&&marker.role.equals("selected")&&marker.latencyMs==0&&f.activity.mapView.renders(marker),"shipping external pin changed exact coordinates/role or invented measurement");check(f.activity.nodeButton.getText().toString().contains("Chicago"),"selected external location label is not displayed");
   f.activity.currentExternalReceipt=new UsageActivity.UnprovedExternalReceipt(e.id);f.activity.map();check(f.activity.currentExternalReceipt.checks>0&&f.activity.mapView.markers.get(0).latencyMs==0,"external map accepted an unowned live measurement");f.activity.currentExternalReceipt=null;
   e.latitude=0d;e.longitude=0d;f.exits.save(e);f.activity.map();check(f.activity.mapView.markers.size()==1&&f.activity.mapView.markers.get(0).latitude==0&&f.activity.mapView.markers.get(0).longitude==0&&f.activity.mapView.renders(f.activity.mapView.markers.get(0)),"valid explicit zero coordinates disappeared from shipping map");
   e.latitude=null;e.longitude=null;f.exits.save(e);f.activity.map();check(f.activity.mapView.markers.isEmpty()&&f.activity.nodeButton.getText().toString().contains("Chicago"),"clearing coordinates retained the old pin or removed its independent label");
  }
 }
 static void pairFrames(Path root)throws Exception{
  try(Fixture f=new Fixture(root)){
   int coord=0;
   for(var node:List.of(f.a,f.b)){
    var data=new JSONObject(Files.readString(node.file.toPath()));
    data.getJSONArray("routerProfiles").getJSONObject(0).put("latitude",30+coord).put("longitude",40+coord);
    AndroidPrivateFileStore.write(node.file,data.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8),AndroidNodeStore.MAX_BUNDLE);coord+=15;
   }
   var loc=f.exits.get(f.x.id);loc.latitude=12d;loc.longitude=33d;f.exits.save(loc);
   var map=f.activity.mapView;var prefs=f.activity.mapPreferences();
   prefs.edit().putBoolean("multihop_on",true).putString("selected_kind","router-vpn").putString("selected_id",f.b.id).putString("multihop_entry",f.a.id).putString("multihop_exit",f.b.id).apply();
   long now=MapCanvasBoundary.SystemClock.now;
   var good=new MapCanvasBoundary.Location(now-2_000_000_000L,12,34,20f);
   map.permission=false;map.onWindowFocusChanged(true);
   check("Locate me".equals(map.advertisedAction())&&map.activity.permissionPrompts==0,"focused map requested location before activation");
   map.setMarkers(List.of(new RouterVpnNodeMapView.Marker("test","Test",10,10,"normal")));
   int[] markerClicks={0};map.markerClickListener=marker->markerClicks[0]++;
   map.touch(0,337,179);map.touch(1,337,179);
   map.touch(0,20,200);map.touch(1,20,200);
   map.touch(0,20,200);map.touch(1,590,30);
   map.touch(0,590,30);map.touch(3,590,30);map.touch(1,590,30);
   check(markerClicks[0]==1&&map.activity.permissionPrompts==0,"marker, blank or cancelled touch requested location");
   check(map.performClick()&&map.activity.permissionPrompts==1&&"Cancel location request".equals(map.advertisedAction()),"accessible map activation did not own one explicit permission request");
   map.performClick();map.permission=true;map.onWindowFocusChanged(true);
   check(map.locationManager.listener==null&&"Locate me".equals(map.advertisedAction()),"cancelled accessibility action started a fix when focus returned");
   map.locationManager.cached=good;map.touch(0,590,30);map.touch(1,590,30);
   check(map.frame().userPins==1&&"Hide my location".equals(map.advertisedAction()),"location button and accessibility action did not share the fresh fix");
   var hidden=map.locationManager.listener;map.performClick();hidden.onLocationChanged(good);
   check(map.frame().userPins==0&&"Locate me".equals(map.advertisedAction()),"accessible Hide retained a pin or accepted the old listener");
   map.locationManager.cached=good;map.requestFix();var retired=map.locationManager.listener;
   check(map.frame().userPins==1&&map.delay==28_000,"cached fix did not keep its original monotonic deadline");
   MapCanvasBoundary.SystemClock.now+=28_000_000_000L;
   check(map.frame().userPins==0,"expired location remained visible without a new map refresh");
   map.delayed.run();check(map.locationManager.listener==null&&map.delayed==null,"idle expiry retained its provider registration");
   map.locationManager.cached=null;map.requestFix();var current=map.locationManager.listener;
   var fresh=new MapCanvasBoundary.Location(MapCanvasBoundary.SystemClock.now,10,20,10f);
   retired.onLocationChanged(fresh);check(map.frame().userPins==0,"a retired location request revived the pin after a new request");
   current.onLocationChanged(new MapCanvasBoundary.Location(fresh.at+1,10,20,5));check(map.frame().userPins==0,"future monotonic fix admitted");
   current.onLocationChanged(new MapCanvasBoundary.Location(fresh.at,10,20,Float.NaN));check(map.frame().userPins==0,"nonfinite accuracy admitted");
   current.onLocationChanged(fresh);check(map.frame().userPins==1,"fresh authorized fix not displayed");
   map.permission=false;check(map.frame().userPins==0,"location pin remained visible after permission revocation");
   map.permission=true;map.hideFix();current.onLocationChanged(fresh);check(map.frame().userPins==0,"queued fix restored hidden pin");
   map.locationManager.cached=fresh;map.requestFix();current=map.locationManager.listener;map.onDetachedFromWindow();current.onLocationChanged(fresh);
   check(map.delayed==null&&map.frame().userPins==0,"detached map retained location or deadline");
   map.requestFix();f.activity.map();var frame=map.frame();
   check(frame.landDraws==1 && frame.segments==1 && frame.entries==1 && frame.exits==1 && frame.locateButtons==1 && frame.userPins==1,"saved pair lost its real preview line, roles or location button");
   check(frame.packets==0 && map.nextFrames==0,"disconnected saved pair painted a packet or scheduled a frame");
   f.controller.connectMultihop(f.a,f.b,"shadowsocks","auto","wg",f.callback);f.finish();f.activity.map();frame=map.frame();
   check(frame.segments==1 && frame.packets==1 && map.nextFrames==1,"proved pair did not paint a packet and schedule its next frame");
   prefs.edit().putString("selected_kind","external").putString("selected_id",f.x.id).putString("multihop_entry",f.b.id).putString("multihop_exit",f.x.id).apply();
   f.activity.map();frame=map.frame();
   check(map.orderedPath.equals(List.of("router-vpn:"+f.a.id,"router-vpn:"+f.b.id)) && frame.packets==1 && map.nextFrames==1,"a newly selected pair inherited another connection's packet");
   f.idle();frame=map.frame();
   check(frame.packets==0 && map.nextFrames==0,"already queued frame animated the retired native owner before UI refresh");
   f.activity.map();frame=map.frame();
   check(map.orderedPath.equals(List.of("router-vpn:"+f.b.id,"external:"+f.x.id)) && frame.segments==1 && frame.entries==1 && frame.exits==1 && frame.packets==0 && map.nextFrames==0,"queued draw after retirement animated the saved replacement or lost its preview");
   f.controller.connectExternal(f.b,loc,false,"wg","local",f.callback);f.finish();f.activity.map();frame=map.frame();
   check(map.orderedPath.equals(List.of("router-vpn:"+f.b.id,"external:"+loc.id)) && frame.packets==1 && map.nextFrames==1,"proved pair with an external exit lost its own packet");
   var activeMarkers=new ArrayList<>(map.markers);
   map.setOrderedPath(List.of("router-vpn:"+f.a.id,"missing-middle","external:"+loc.id),true,null);frame=map.frame();
   check(frame.segments==0 && frame.packets==0 && map.nextFrames==0,"missing ordered coordinate invented a direct segment or queued a frame");
   activeMarkers.add(new RouterVpnNodeMapView.Marker("middle","Middle",11d,56d,RouterVpnNodeMapView.ROLE_HOP));
   map.setMarkers(activeMarkers);map.setOrderedPath(List.of("router-vpn:"+f.a.id,"middle","external:"+loc.id),true,null);frame=map.frame();
   check(frame.segments==2 && frame.packets==2 && map.nextFrames==1,"proved ordered path lost a segment or scheduled more than one next frame");
   for(double first:List.of(179d,-179d,180d,-180d)){
    map.setMarkers(List.of(new RouterVpnNodeMapView.Marker("west","West",10,first,"entry"),new RouterVpnNodeMapView.Marker("east","East",20,-first,"exit")));
    map.setOrderedPath(List.of("west","east"),true,()->true);
    for(long instant:List.of(0L,450_000_000L,900_000_000L,1_350_000_000L)){
     MapCanvasBoundary.SystemClock.now=instant;
     var crossing=map.frame();
     check(crossing.segments==(Math.abs(first)==180?1:2)&&crossing.longestX<4,"date-line hop crossed the long way through the map");
     check(crossing.packets==1&&(crossing.packetX<18||crossing.packetX>622),"animated date-line packet left its short route");
    }
   }
  }
 }
 static JSONObject orderedBundle(int position)throws Exception{
  var keys=java.security.KeyPairGenerator.getInstance("X25519");var server=keys.generateKeyPair();var client=keys.generateKeyPair();
  byte[] integer=((java.security.interfaces.XECPublicKey)server.getPublic()).getU().toByteArray(),publicKey=new byte[32];
  for(int i=0;i<Math.min(integer.length,publicKey.length);i++)publicKey[i]=integer[integer.length-1-i];
  String peer=java.util.Base64.getEncoder().encodeToString(publicKey);
  String proof=java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(("router-vpn-node-proof-v1\n"+peer).getBytes(java.nio.charset.StandardCharsets.UTF_8)));
  String privateKey=java.util.Base64.getEncoder().encodeToString(((java.security.interfaces.XECPrivateKey)client.getPrivate()).getScalar().orElseThrow());
  String config="[Interface]\nAddress=10.77.0.2/32\nPrivateKey="+privateKey+"\nDNS=192.168.50.133\nMTU=1280\n[Peer]\nPublicKey="+peer+"\nEndpoint=192.0.2.10:51820\nAllowedIPs=0.0.0.0/0\n";
  JSONObject value=bundle(proof,"Ordered "+position,0);
  value.getJSONObject("profiles").put("wg",new JSONObject().put("wg.conf",java.util.Base64.getEncoder().encodeToString(config.getBytes(java.nio.charset.StandardCharsets.UTF_8))));
  return value;
 }
 static AndroidNodeStore.ChainCapture ordered(Fixture f)throws Exception{
  f.store.remove(f.a.id);f.store.remove(f.b.id);JSONArray refs=new JSONArray();
  for(int i=0;i<3;i++)refs.put(new JSONObject().put("id","ordered-"+i).put("mode",i==2?"shadowsocks":"wg"));
  AndroidNodeStore.Node control=null;
  for(int i=0;i<3;i++){
   JSONObject b=orderedBundle(i);JSONObject p=b.getJSONArray("routerProfiles").getJSONObject(0);
   p.put("id","ordered-"+i);b.put("selectedRouterID","ordered-"+i).put("activeRouterProfileId","ordered-"+i);
   if(i!=1)p.put("latitude",10+i).put("longitude",20+i);
   if(i==2){p.put("multihop_enabled",true).put("multihop_execution","local").put("multihop_nodes",refs);b.getJSONObject("profiles").put("shadowsocks",new JSONObject().put("fixture","controlled-native-boundary"));}
   control=f.store.importBundle(b.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
  }
  f.activity.mapPreferences().edit().putString("selected_kind","router-vpn").putString("selected_id",control.id).putBoolean("multihop_on",true).putString("multihop_nodes",refs.toString()).apply();
  return f.store.captureChain(control.id);
 }
 static void orderedIdentity(Path root)throws Exception{
  for(String fault:List.of("missing-wg","short-key"))try(Fixture f=new Fixture(root)){
   var captured=ordered(f);File member=f.store.file(captured.control.id);JSONObject source=new JSONObject(Files.readString(member.toPath()));
   if(fault.equals("missing-wg"))source.getJSONObject("profiles").remove("wg");
   else{
    source.getJSONObject("profiles").getJSONObject("wg").put("wg.conf",java.util.Base64.getEncoder().encodeToString("[Peer]\nPublicKey=AQ==\n".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    String proof=java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest("router-vpn-node-proof-v1\nAQ==".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    source.put("nodeProofId",proof);source.getJSONArray("routerProfiles").getJSONObject(0).put("node_proof_id",proof);
   }
   // Publish a coherent legacy-compatible catalog and active selection through
   // the real store. A raw file edit would test stale-source refusal first and
   // would not prove that ordered capture requires the original WG companion.
   f.store.remove(captured.control.id);
   var replacement=f.store.importBundle(source.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
   f.activity.mapPreferences().edit().putString("selected_id",replacement.id).apply();
   boolean refused=false;try{f.store.captureChain(replacement.id);}catch(Exception expected){refused=true;}
   check(refused&&!f.usage().exists(),"ordered capture accepted missing original WG companion: "+fault);
  }
 }
 static JSONObject orderedProgress(AndroidNodeStore.ChainCapture captured)throws Exception{
  JSONArray prefixes=new JSONArray();for(int i=0;i<captured.members.size();i++)prefixes.put(new JSONObject().put("position",i).put("profile_id",captured.members.get(i).profileId).put("response_ms",10.0+i).put("proven",true));
  return new JSONObject().put("complete",true).put("ready",true).put("execution","local").put("prefixes",prefixes);
 }
 static void orderedUsage(Path root)throws Exception{
  for(String fault:List.of("","source","order","mode","control","stop"))try(Fixture f=new Fixture(root)){
   var captured=ordered(f);var attempt=AndroidNodeUsage.ordered(f.activity,f.store,captured);var home=AndroidHomeStateStore.beginNodeChain(f.activity,captured);attempt.owned(f.activity,home.sessionId);
   check(AndroidHomeStateStore.connectedNodeChain(f.activity,home),"controlled ordered native boundary could not adopt original Home");
   if(fault.equals("source"))Files.writeString(f.store.file(captured.members.get(1).id).toPath(),"changed middle source");
   if(fault.equals("order")||fault.equals("mode")){JSONArray altered=new JSONArray(home.activeChain);if(fault.equals("order")){JSONObject first=altered.getJSONObject(0);altered.put(0,altered.getJSONObject(1));altered.put(1,first);}else altered.getJSONObject(1).put("mode","shadowsocks");f.activity.getSharedPreferences("routervpn_home_state_v1",0).edit().putString("active_chain",altered.toString()).apply();}
   if(fault.equals("control"))f.activity.getSharedPreferences("routervpn_home_state_v1",0).edit().putString("active_node_id",captured.members.get(0).id).apply();
   if(fault.equals("stop"))AndroidHomeStateStore.advancePathGeneration(f.activity);
   String result=attempt.finished(f.activity,"f".repeat(32),true);
   if(fault.isEmpty()){check(result.isEmpty(),"ordered original proof usage was not saved");for(var member:captured.members)check(f.count("router-vpn",member.id)==1,"ordered usage omitted an original member");byte[] saved=f.read(f.usage());attempt.finished(f.activity,"f".repeat(32),true);check(Arrays.equals(saved,f.read(f.usage())),"ordered usage counted duplicate completion");}
   else check(!result.isEmpty()&&!f.usage().exists(),"ordered usage accepted a changed source or graph: "+fault);
  }
 }
 static void orderedPresentation(Path root)throws Exception{
  try(Fixture f=new Fixture(root)){
   var captured=ordered(f);var home=AndroidHomeStateStore.beginNodeChain(f.activity,captured);check(AndroidHomeStateStore.connectedNodeChain(f.activity,home),"ordered display Home setup failed");
   var runtime=AndroidRuntimeRegistry.get(f.activity).nodeChain;runtime.active=new AndroidNodeChainRuntime.ActiveCapture(captured,home,orderedProgress(captured).toString());
   AtomicReference<AndroidOrderedPathPresentation> result=new AtomicReference<>();AtomicReference<Throwable> error=new AtomicReference<>();
   Thread worker=new Thread(()->{try{result.set(AndroidOrderedPathPresentation.capture(f.activity,f.store,f.exits,runtime));}catch(Throwable e){error.set(e);}},"ordered-render-worker");worker.start();worker.join(4000);
   check(!worker.isAlive()&&error.get()==null&&result.get()!=null,"ordered worker could not capture the original receipt: "+error.get());f.activity.orderedPresentation=result.get();int reads=runtime.activeReads;
   for(int i=0;i<10;i++)f.activity.map();
   check(runtime.activeReads==reads,"ordered UI render reread the native owner");
   check(f.activity.mapView.orderedPath.size()==3&&f.activity.mapView.orderedLive&&f.activity.mapView.markers.size()==2,"ordered map omitted the unlocated middle identity or invented its coordinates");
   for(var marker:f.activity.mapView.markers)check(marker.name.contains("routed HTTP proof")&&marker.latencyMs>=10&&marker.latencyMs<=12,"ordered map borrowed ordinary catalog latency or mislabeled HTTP proof");
   for(String kind:List.of("routed HTTP proof","HTTPS")){var marker=new RouterVpnNodeMapView.Marker("long","A deliberately very long original node name • "+kind,10,20,"entry",12.5);check(marker.label().contains("…")&&marker.label().endsWith("12.5 ms "+kind),"rendered map truncated its measured protocol: "+kind);}
   JSONObject mismatched=orderedProgress(captured);mismatched.getJSONArray("prefixes").getJSONObject(1).put("profile_id",captured.members.get(0).profileId);runtime.active=new AndroidNodeChainRuntime.ActiveCapture(captured,home,mismatched.toString());
   boolean refused=false;try{AndroidOrderedPathPresentation.capture(f.activity,f.store,f.exits,runtime);}catch(Exception expected){refused=true;}check(refused,"ordered display accepted another prefix's response");
   AndroidHomeStateStore.advancePathGeneration(f.activity);check(f.activity.currentOrderedPresentation()==null,"ordered display survived a completed stop generation");f.activity.map();check(!f.activity.mapView.orderedLive,"ordered map animated a retired receipt");
  }
 }
 public static void main(String[] args)throws Exception{importedCaptureBoundary();savedPolicyValidation();Path root=Path.of(args[0]);if(args.length>1){if(!List.of("imported-packet","imported-socks").contains(args[1]))throw new AssertionError("Unknown usage family");importedProtocols=args[1].equals("imported-socks")?List.of("socks5"):List.of("wireguard","amneziawg");importedExclusions(root);System.out.println("Android "+args[1]+" entry usage: "+checks+" shipping controller/store/Home checks PASS (native proof boundary controlled)");return;}externalMap(root);pairFrames(root);ordinary(root);excluded(root);importedExclusions(root);stableIdentity(root);failedStore(root);atomicOwner(root);ranking(root);externalActivity(root);orderedIdentity(root);orderedUsage(root);orderedPresentation(root);System.out.println("Android node usage: "+checks+" shipping controller/store/Home/catalog/management checks PASS (native proof boundary controlled)");}
}
'''


def sources():
    ui = dict(P.T.UI)
    ui['android/content/SharedPreferences.java'] = S.PREFS
    ui['android/content/MemoryPreferences.java'] = S.MEMORY
    ui['android/content/Context.java'] = ui['android/content/Context.java'].replace('return (key,fallback)->fallback;', 'return preferences.computeIfAbsent(name,key->new MemoryPreferences());').replace('public static final int MODE_PRIVATE=0;', 'public static final java.util.Map<String,MemoryPreferences> preferences=new java.util.LinkedHashMap<>();public static final int MODE_PRIVATE=0;')
    ui['android/os/Bundle.java'] = ui['android/os/Bundle.java'][:-1] + 'public void putStringArrayList(String k,java.util.ArrayList<String> v){values.put(k,new java.util.ArrayList<>(v));}public java.util.ArrayList<String> getStringArrayList(String k){return (java.util.ArrayList<String>)values.get(k);}public boolean containsKey(String k){return values.containsKey(k);}}'
    ui['android/util/Base64.java'] = 'package android.util;public final class Base64{public static final int DEFAULT=0,NO_WRAP=2;public static byte[] decode(String raw,int flags){return java.util.Base64.getMimeDecoder().decode(raw);}public static String encodeToString(byte[] raw,int flags){return java.util.Base64.getEncoder().encodeToString(raw);}}'
    ui['android/system/Os.java'] = OS
    ui['android/system/OsConstants.java'] = 'package android.system;public final class OsConstants{public static final int S_IFMT=0170000,S_IFREG=0100000,S_IFDIR=0040000,ENOENT=2;}'
    ui['android/system/ErrnoException.java'] = 'package android.system;public final class ErrnoException extends Exception{public final int errno;public ErrnoException(String operation,int errno){super(operation);this.errno=errno;}}'
    ui['android/system/StructStat.java'] = 'package android.system;public final class StructStat{public final int st_mode;public final long st_dev,st_ino,st_size;public StructStat(int m,long d,long i,long s){st_mode=m;st_dev=d;st_ino=i;st_size=s;}}'
    ui['com/wireguard/android/backend/Tunnel.java'] = 'package com.wireguard.android.backend;public interface Tunnel{enum State{UP,DOWN}}'
    ui['org/amnezia/awg/backend/Tunnel.java'] = 'package org.amnezia.awg.backend;public interface Tunnel{enum State{UP,DOWN}}'
    ui['io/nekohasekai/libbox/Libbox.java'] = S.PRIVATE_JSON_JAVA.replace('public final class Libbox {',
        'public final class Libbox {public static String routerNodeChainImportedOpenVPNMemberInput(String source,String capture){throw new AssertionError("Usage fixture cannot compile a native OpenVPN member.");}')
    boundaries = P.BOUNDARIES
    # The actual saved-exit store validates hostname policy even in usage/UI
    # composition. Extract its shipping validator and complete pure dependency
    # closure; native profile construction remains an explicit separate boundary.
    policy = (JAVA / 'AndroidExternalPolicy.java').read_text()
    constants = "\n".join(line for line in policy.splitlines() if 'static final int MAX_CAPTURE =' in line)
    start = policy.index('    private static final Set<String> POLICY =')
    constants += "\n" + policy[start:policy.index(';', start) + 1]
    methods = "\n".join(S.block(policy, signature) for signature in ('    static void checkPolicy(', '    private static boolean bounded(',
        '    static final class Captured {', '    static Captured captureImportedEntry('))
    # Imported capture's public validation and defensive copy are shipping
    # code. This usage-only fixture still cannot compile or adopt a native
    # transport; its private composition boundary must always refuse.
    methods += r'''
 static AndroidStandardExitStore.Entry refusedImportedCapture;static int importedCaptureCalls;
 private static Captured capture(AndroidStandardExitStore.Entry entry,JSONObject predecessor,String mode,Object captured,String execution)throws Exception{
  if(predecessor!=null||captured!=null||!"external".equals(mode)||!"local".equals(execution))throw new AssertionError("Usage imported capture changed its bounded composition request.");
  importedCaptureCalls++;refusedImportedCapture=entry;
  throw new AssertionError("Usage fixture has no native imported capture authority.");
 }
'''
    assert boundaries.count('final class AndroidExternalPolicy {') == 1
    boundaries = boundaries.replace('final class AndroidExternalPolicy {', 'final class AndroidExternalPolicy {' + constants + methods)
    # This fixture uses the actual checked-exception store API, while the
    # permission fixture doubles that store. Keep the compiler seam explicit.
    boundaries = boundaries.replace('static void requireEntry(AndroidStandardExitStore.Entry e){', 'static void requireEntry(AndroidStandardExitStore.Entry e)throws Exception{')
    boundaries = boundaries.replace('static void compile(AndroidStandardExitStore.Entry e,JSONObject b,String mode,String execution){', 'static void compile(AndroidStandardExitStore.Entry e,JSONObject b,String mode,String execution)throws Exception{')
    for name in ('AndroidPrivateFileStore', 'AndroidNodeUsage', 'AndroidHomeStateStore', 'AndroidNodeStore', 'AndroidStandardExitStore', 'AndroidModeOrchestrator', 'AndroidMultihopRuntime', 'AndroidStandardExitRuntime'):
        boundaries = S.replace_class(boundaries, name, '')
    boundaries = boundaries.replace('throw new AssertionError("unexpected startup capture");', '')
    boundaries = boundaries.replace('AndroidHomeStateStore.Snapshot idleOwner(){throw new AssertionError("unexpected startup idle capture");}', 'final AndroidHomeStateStore.Snapshot capturedIdle=AndroidHomeStateStore.snapshot(new Context());AndroidHomeStateStore.Snapshot idleOwner(){return capturedIdle;}')
    boundaries = boundaries.replace('final class NativeWireGuardController {}', 'final class NativeWireGuardController {com.wireguard.android.backend.Tunnel.State getState(){return com.wireguard.android.backend.Tunnel.State.DOWN;}}').replace('final class NativeAmneziaWGController {}', 'final class NativeAmneziaWGController {org.amnezia.awg.backend.Tunnel.State getState(){return org.amnezia.awg.backend.Tunnel.State.DOWN;}}').replace('final class NativeXrayController {}', 'final class NativeXrayController {String getState(){return "DOWN";}}')
    boundaries = boundaries.replace('final class NativeSingBoxController {', 'final class NativeSingBoxController {String getState(){return "DOWN";}')
    boundaries = boundaries.replace('static boolean isTor(String p)', 'static void validate(AndroidStandardExitStore.Entry e){}static boolean isTor(String p)')
    boundaries = boundaries.replace('ExternalSelection currentExternalPath(String id)', 'void selectOrdinaryTorPath(AndroidStandardExitStore.Entry exit,AndroidStandardExitStore.Entry entry){}ExternalSelection currentExternalPath(String id)')
    native = (JAVA / 'NativeSingBoxController.java').read_text()
    methods = [S.block(native, '    static boolean ' + name + '(') for name in ('nativeMultihopEntry', 'nativeWireGuardFamily', 'nativeNaiveFamily', 'nativePQFamily')]
    boundaries = boundaries.replace(' // PRODUCTION_TRANSPORT_PREDICATES', '\n'.join(methods)).replace(' // PRODUCTION_COMPOSITE_PREDICATE', S.block((JAVA / 'AndroidNativeCompositeProfile.java').read_text(), '    static boolean isMode('))
    # Usage and presentation retain purpose identity but never launch a candidate VPN.
    preparation_start = 'void start(){if(cancelled||retired||started)throw new IllegalStateException("retired original preparation");started=true;starts++;homeSession="temporary-purpose";AndroidHomeStateStore.current.sessionId=homeSession;AndroidHomeStateStore.current.connected=true;AndroidHomeStateStore.current.phase="connected";AndroidHomeStateStore.current.pathProof="passed";}'
    assert boundaries.count(preparation_start) == 1
    boundaries = boundaries.replace(preparation_start, 'void start(){throw new AssertionError("usage fixture must not start candidate permission flow");}')
    boundaries += NATIVE.replace(' // MULTIHOP_CAPTURE_TYPES', P.MULTIHOP_CAPTURE_TYPES)
    protection = S.block(boundaries, 'final class AndroidExternalProtection')
    assert boundaries.count(protection) == 1
    boundaries = boundaries.replace(protection, S.block((JAVA / 'AndroidExternalProtection.java').read_text(), 'final class AndroidExternalProtection'))
    import android_store_fixture
    boundaries+="\n"+"final class "+android_store_fixture.ordered_shape().split("final class ",1)[1]
    return ui, boundaries


def main():
    if os.name != 'posix' or not Path('/proc/self/fd').is_dir():
        raise RuntimeError('The real Unix private-file adapter requires Linux /proc file descriptors')
    jar = Path(os.environ.get('ANDROID_JSON_JAR', '/usr/share/java/com.android.json.jar'))
    if not jar.is_file():
        raise RuntimeError('Android JSON JAR is required')
    ui, boundaries = sources()
    boundaries = boundaries.replace('final class AndroidStandardExitRuntime {', 'final class AndroidStandardExitRuntime {' + P.UNOWNED_EXTERNAL_RESTORE_SOURCE)
    callback = S.block((JAVA / 'ProductActivity.java').read_text(), '    private AndroidUnifiedConnectionController.Callback callback(')
    product=(JAVA / 'ProductActivity.java').read_text()
    publication=S.block((JAVA/'AndroidConnectionProfileStore.java').read_text(),'    static void applySelection(')
    assert boundaries.count('final class AndroidConnectionProfileStore {')==1
    boundaries=boundaries.replace('import android.content.Context;','import android.content.Context;import android.content.SharedPreferences;').replace('final class AndroidConnectionProfileStore {','final class AndroidConnectionProfileStore {'+publication)

    map_constants='\n'.join(line for line in product.splitlines() if any(key in line for key in ('private static final String PREFS=', 'private static final String MODE_KEY=', 'private static final String MULTI_ON=')))
    with tempfile.TemporaryDirectory(prefix='routervpn-usage-') as directory, tempfile.TemporaryDirectory(prefix='.usage-json-', dir=ROOT) as validator_directory:
        root = Path(directory)
        validator_source = Path(validator_directory) / 'main.go'
        validator_source.write_text(S.PRIVATE_JSON_GO.replace('4097', '98305').replace('4096', '98304'))
        validator = root / 'private-json'
        subprocess.run(['go', 'build', '-o', str(validator), str(validator_source)], cwd=ROOT, check=True, timeout=120)
        for path, source in ui.items():
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source)
        app = root / 'com/eabusham/routervpn'
        app.mkdir(parents=True)
        (app / 'Boundaries.java').write_text(boundaries)
        (app / 'UsageActivity.java').write_text(ACTIVITY.replace(' // SHIPPING_EXTERNAL_LATENCY', S.block(product, '    private double liveExternalMedian(')).replace(' // SHIPPING_CALLBACK', callback).replace(' // SHIPPING_MAP_PROJECTION', S.block(product, '    private void refreshNodes(')).replace(' // SHIPPING_MAP_CONSTANTS', map_constants).replace(' // SHIPPING_PREFS', S.block(product, '    private SharedPreferences prefs(')).replace(' // SHIPPING_MAP_MARKER', S.block((JAVA / 'RouterVpnNodeMapView.java').read_text(), '    static final class Marker')).replace(' // SHIPPING_MAP_VALID', S.block((JAVA / 'RouterVpnNodeMapView.java').read_text(), '    private boolean valid(Marker m)')))
        external = (JAVA / 'StandardExitActivity.java').read_text()
        start = external.index('\n', external.index('public final class StandardExitActivity'))
        fields = external[start:external.index('    @Override protected void onCreate(')]
        signatures = ('    private void dialog(', '    @Override protected void onDestroy()', '    @Override protected void onSaveInstanceState(', '    private void restorePending(',
                      '    private boolean selectionOnly(', '    private void requestDirect(', '    private void requestOrdinaryTor(',
                      '    private void requestConnect(AndroidNodeStore.Node entry,AndroidStandardExitStore.Entry exit,String entryMode,String execution)',
                      '    private void capturePending(AndroidNodeStore.Node entry,AndroidStandardExitStore.Entry exit,boolean direct,String entryMode)',
                      '    private void capturePending(AndroidNodeStore.Node entry,AndroidStandardExitStore.Entry exit,boolean direct,String entryMode,String execution)',
                      '    private static String requestDigest(', '    private static String ordinaryRequestDigest(', '    private void captureUsage(',
                      '    private boolean ownsUsage(', '    private void releaseUsage(', '    private UsagePermission takeUsage(', '    private void clearPending(',
                      '    private void startPending(', '    private boolean activeOrTransitioning(', '    @Override protected void onActivityResult(')
        (app / 'StandardExitActivity.java').write_text(EXTERNAL_ACTIVITY.replace(' // SHIPPING_FIELDS', fields).replace(' // SHIPPING_METHODS', '\n'.join(S.block(external, signature) for signature in signatures)))
        (app / 'NodeUsageTest.java').write_text(HARNESS)
        names = ('AndroidPrivateFileStore', 'AndroidNodeUsage', 'AndroidHomeStateStore', 'AndroidNodeStore', 'AndroidStandardExitStore', 'AndroidProfileSelection', 'AndroidUnifiedNodeCatalog', 'AndroidConnectionSelection', 'AndroidUnifiedConnectionController', 'AndroidNumericAddress', 'AndroidOrderedPathPresentation')
        for name in names:
            (app / (name + '.java')).write_bytes((JAVA / (name + '.java')).read_bytes())
        compile = ['javac', '--release', '17', '-encoding', 'UTF-8', '-proc:none', '-cp', str(jar), '-d', str(root / 'classes'), *map(str, root.rglob('*.java'))]
        run = ['java', '--add-opens=java.base/java.io=ALL-UNNAMED', '-Dfixture.privatejson=' + str(validator), '-cp', os.pathsep.join((str(root / 'classes'), str(jar))), 'com.eabusham.routervpn.NodeUsageTest', str(root / 'data')]
        (root / 'data').mkdir()
        subprocess.run(compile, check=True, timeout=45)
        subprocess.run(run, check=True, timeout=60)
        subprocess.run([*run, "imported-packet"], check=True, timeout=60)
        subprocess.run([*run, "imported-socks"], check=True, timeout=60)
        controls = (
            ('Boundaries.java', 'capture(AndroidStandardExitStore.copy(entry), null, "external", null, "local")', 'capture(entry, null, "external", null, "local")', 'usage imported capture omitted its original defensive source copy'),
            ('Boundaries.java', 'throw new AssertionError("Usage fixture has no native imported capture authority.");', 'return new Captured("{}","{}");', 'usage fixture fabricated native imported capture authority'),
            ('Boundaries.java', '!POLICY.contains(keys.getString(i))', 'false', 'saved hostname policy accepted malformed unknown-field'),
            ('Boundaries.java', '!(policy.get("kill_switch") instanceof Boolean)', 'false', 'saved hostname policy accepted malformed protection-type'),
            ('AndroidNodeStore.java', '            source.requirePairedIdentity();', '            /* defect: omit original ordered identity source */', 'ordered capture accepted missing original WG companion: missing-wg'),
            ('UsageActivity.java', 'currentExternalReceipt.requireCurrent();', '', 'external map accepted an unowned live measurement'),
            ('AndroidNodeUsage.java', 'nodes.size()>MAX_RECORDS', 'nodes.size()>2', 'ordered original proof usage was not saved'),
            ('AndroidNodeUsage.java', '!sameChain(chain,home.activeChain)', 'false', 'ordered usage accepted a changed source or graph: order'),
            ('AndroidOrderedPathPresentation.java', '!sources.get(i).profileId.equals(prefix.optString("profile_id"))', 'false', "ordered display accepted another prefix's response"),
            ('UsageActivity.java', 'presentation.members.get(position).httpResponseMs', '0', 'ordered map borrowed ordinary catalog latency or mislabeled HTTP proof'),
            ('UsageActivity.java', 'if(!measurement.isEmpty())label+=" "+measurement;', '', 'rendered map truncated its measured protocol: routed HTTP proof'),
            ('AndroidNodeUsage.java', '!AndroidImportedRouterPath.supports(entry.protocol,exitMode)', '!Arrays.asList("shadowsocks","hysteria2","wireguard","amneziawg").contains(entry.protocol)', 'imported usage conflated same text IDs across original node kinds: socks5'),
            ('AndroidNodeUsage.java', 'Arrays.asList(captureExternal(context,entry),captureRouter(exit))', 'Collections.singletonList(captureRouter(exit))', 'imported multihop did not count both original typed nodes'),
            ('AndroidNodeUsage.java', 'entry.id,exit.id,entry.protocol,"",false)', 'entry.id,exit.id,"shadowsocks","",false)', 'imported usage conflated same text IDs across original node kinds: hysteria2'),
            ('UsageActivity.java', '(m.explicitCoordinates||!(m.latitude==0&&m.longitude==0))', '!(m.latitude==0&&m.longitude==0)', 'valid explicit zero coordinates disappeared from shipping map'),
            ('AndroidUnifiedNodeCatalog.java', 'exit.protocol,exit.expectedPublicIp,exit.location,exit.latitude,exit.longitude,null,null,0,', 'exit.protocol,exit.expectedPublicIp,"",null,null,null,null,0,', 'external catalog lost explicit coordinates/location or invented latency'),
            ('AndroidNodeUsage.java', 'for(Node node:nodes)node.source.requireCurrent();', '/* broken: no source binding */', 'invalid adoption recorded usage: source'),
            ('UsageActivity.java', 'mapView.setOrderedPath(mapOrder,live,frameOwner);', 'mapView.setOrderedPath(mapOrder,!mapOrder.isEmpty(),frameOwner);', 'disconnected saved pair painted a packet or scheduled a frame'),
            ('UsageActivity.java', 'frameOwner=()->AndroidHomeStateStore.ownsPairFrame(this,home);', 'frameOwner=()->true;', 'already queued frame animated the retired native owner before UI refresh'),
            ('UsageActivity.java', 'if(!active.isEmpty()) {', 'if(!active.isEmpty()&&prefs().getString(SELECTED_KIND,"router-vpn").equals("router-vpn")) {', "a newly selected pair inherited another connection's packet"),
            ('AndroidNodeUsage.java', 'requireOwner(home);', '/* broken: no proved owner */', 'invalid adoption recorded usage: owner'),
            ('AndroidUnifiedConnectionController.java', 'if(!callback.recordsNodeUsage()||pendingStartup!=null)return null;', 'if(pendingStartup!=null)return null;', 'temporary trial counted as user adoption: router'),
            ('AndroidUnifiedConnectionController.java', 'if(!callback.recordsNodeUsage()||pendingStartup!=null)return null;', 'if(!callback.recordsNodeUsage())return null;', 'automatic startup counted as user adoption'),
            ('AndroidNodeUsage.java', 'Math.max(node.imported.count,same?previous.getInt("count"):0)', 'node.imported.count+(same?previous.getInt("count"):0)', 'imported count was repeatedly added instead of maximum'),
            ('StandardExitActivity.java', 'if(usage!=null)usage.usage.owned(StandardExitActivity.this,session);', '/* broken: management owner omitted */', 'management final node use missing'),
            ('StandardExitActivity.java', '}else if(!nonce.isEmpty())clearPending();', '}/* broken: cancelled process receipt ignored */', 'cancelled/recreated management receipt was replayed: cancelled'),
        )
        for name, old, new, assertion in controls:
            target = app / name
            original = target.read_text()
            assert original.count(old) == 1, (name, old)
            target.write_text(original.replace(old, new))
            subprocess.run(compile, check=True, timeout=45, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            broken = subprocess.run([*run, "imported-socks"] if assertion.endswith(": socks5") else run, timeout=60, capture_output=True, text=True)
            target.write_text(original)
            assert broken.returncode and assertion in broken.stderr, 'usage negative control missed intended assertion: ' + name + '\n' + broken.stdout + broken.stderr
            print('Android usage negative control rejected:', name, assertion)


if __name__ == '__main__':
    main()
