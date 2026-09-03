package com.eabusham.routervpn;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Activity-owned UI bridge over app-process-owned VPN engines. */
final class AndroidUnifiedConnectionController implements AutoCloseable {
    interface Callback { void progress(String message); void finished(boolean ok, String message); }
    static final int PREPARE_UNIFIED = 7605;
    private static final String STATE_PENDING="routervpn.pending",STATE_MODE="routervpn.pending.mode",STATE_LAYERS="routervpn.pending.layers",STATE_NODE="routervpn.pending.node",STATE_ENTRY="routervpn.pending.entry",STATE_EXIT="routervpn.pending.exit",STATE_EXIT_MODE="routervpn.pending.exit_mode",STATE_STANDARD_EXIT="routervpn.pending.standard_exit",STATE_EXTERNAL_DIRECT="routervpn.pending.external_direct";

    private final Activity activity;
    private final AndroidNodeStore nodeStore;
    private final AndroidStandardExitStore exitStore;
    private final AndroidRuntimeRegistry runtime;
    private final NativeWireGuardController wireGuard;
    private final NativeAmneziaWGController amneziaWG;
    private final NativeSingBoxController singBox;
    private final NativeXrayController xray;
    private final AndroidModeOrchestrator orchestrator;
    private final AndroidMultihopRuntime multihop;

    private String pendingMode = "";
    private List<String> pendingLayers = Collections.emptyList();
    private AndroidNodeStore.Node pendingNode, pendingEntry, pendingExit;
    private AndroidStandardExitStore.Entry pendingStandardExit;
    private boolean pendingExternalDirect;
    private String pendingExitMode = "";
    private Callback pendingCallback;

    AndroidUnifiedConnectionController(Activity activity, AndroidNodeStore nodeStore) {
        this.activity = activity;
        this.nodeStore = nodeStore;
        this.exitStore = new AndroidStandardExitStore(activity);
        runtime = AndroidRuntimeRegistry.get(activity);
        wireGuard = runtime.wireGuard;
        amneziaWG = runtime.amneziaWG;
        singBox = runtime.singBox;
        xray = runtime.xray;
        orchestrator = runtime.orchestrator;
        multihop = runtime.multihop;
    }

    boolean isActiveOrTransitioning() { return AndroidVpnMutationGuard.isBusy(activity); }
    boolean isConnected() { return AndroidHomeStateStore.snapshot(activity).connected; }
    boolean isMultihopConnected() { return multihop.isConnected(); }
    String activeMultihopEntryId() { return multihop.activeEntryId(); }
    String activeMultihopExitId() { return multihop.activeExitId(); }
    String activeMultihopExitMode() { return multihop.activeExitMode(); }
    List<AndroidStandardExitStore.Entry> standardExits() throws Exception { return exitStore.list(); }

    void connect(String mode, List<String> layers, Callback callback) {
        if (isActiveOrTransitioning()) { callback.finished(false, "Disconnect the current Router VPN session or let its transition finish first."); return; }
        try { activeBundle(); } catch (Exception error) { callback.finished(false, safe(error)); return; }
        pendingNode = null; prepareSingleNode(mode,layers,callback);
    }

    /** Explicit/test-only node connection that never mutates AndroidNodeStore.activeId(). */
    void connectNode(AndroidNodeStore.Node node, String mode, List<String> layers, Callback callback) {
        if(node==null||node.file==null||!node.file.isFile()||node.file.length()<=0){callback.finished(false,"Choose a valid stored Router VPN node first.");return;}
        if (isActiveOrTransitioning()) { callback.finished(false, "Disconnect the current Router VPN session or let its transition finish first."); return; }
        pendingNode=node; prepareSingleNode(mode,layers,callback);
    }

    private void prepareSingleNode(String mode,List<String>layers,Callback callback){
        pendingMode = mode == null || mode.trim().isEmpty() ? "smart-auto" : mode.trim().toLowerCase();
        pendingLayers = layers == null ? Collections.emptyList() : new ArrayList<>(layers);
        pendingEntry = null; pendingExit = null; pendingStandardExit=null; pendingExternalDirect=false; pendingExitMode = ""; pendingCallback = callback;
        requestPermission("Router VPN " + displayMode(pendingMode));
    }

    void connectMultihop(AndroidNodeStore.Node entry, AndroidNodeStore.Node exit, String exitMode, Callback callback) {
        if (entry == null || exit == null || entry.id.equals(exit.id)) { callback.finished(false, "Multihop requires two different stored nodes."); return; }
        if (exitMode == null || exitMode.trim().isEmpty()) { callback.finished(false, "Choose a supported multihop exit transport."); return; }
        if (isActiveOrTransitioning()) { callback.finished(false, "Disconnect the current Router VPN session before multihop."); return; }
        pendingNode=null;pendingStandardExit=null;pendingExternalDirect=false;pendingMode="multihop";pendingLayers=Collections.emptyList();pendingEntry=entry;pendingExit=exit;pendingExitMode=exitMode.trim();pendingCallback=callback;
        requestPermission("Router VPN multihop");
    }

    /** Uses the existing proven Android custom-exit runtime under the same VPN-permission owner. */
    void connectExternal(AndroidNodeStore.Node entry, AndroidStandardExitStore.Entry exit, boolean direct, Callback callback) {
        if(exit==null){callback.finished(false,"Choose a stored custom exit first.");return;}
        if(!direct&&(entry==null||entry.file==null||!entry.file.isFile())){callback.finished(false,"Choose a valid Router VPN entry node for the hopped external test.");return;}
        if(isActiveOrTransitioning()){callback.finished(false,"Disconnect the current Router VPN session before a custom-exit test.");return;}
        pendingNode=null;pendingMode="external";pendingLayers=Collections.emptyList();pendingEntry=entry;pendingExit=null;pendingExitMode="";pendingStandardExit=exit;pendingExternalDirect=direct;pendingCallback=callback;
        requestPermission(direct?"direct "+exit.protocol+" custom exit":"Router VPN entry → "+exit.protocol+" custom exit");
    }

    List<NativeSingBoxController.ModeInfo> supportedMultihopExitModes(AndroidNodeStore.Node exit) throws Exception {
        if (exit == null) return Collections.emptyList();
        return multihop.listSupportedExitModes(exit.file);
    }

    void savePending(Bundle out) {
        if (out == null || pendingCallback == null || pendingMode.isEmpty()) return;
        out.putBoolean(STATE_PENDING,true);out.putString(STATE_MODE,pendingMode);out.putStringArrayList(STATE_LAYERS,new ArrayList<>(pendingLayers));
        if(pendingNode!=null)out.putString(STATE_NODE,pendingNode.id);if(pendingEntry!=null)out.putString(STATE_ENTRY,pendingEntry.id);if(pendingExit!=null)out.putString(STATE_EXIT,pendingExit.id);out.putString(STATE_EXIT_MODE,pendingExitMode);
        if(pendingStandardExit!=null)out.putString(STATE_STANDARD_EXIT,pendingStandardExit.id);out.putBoolean(STATE_EXTERNAL_DIRECT,pendingExternalDirect);
    }

    void restorePending(Bundle in, Callback callback) {
        if(in==null||!in.getBoolean(STATE_PENDING,false))return;String mode=in.getString(STATE_MODE,"");if(mode==null||mode.trim().isEmpty())return;pendingMode=mode.trim();ArrayList<String>layers=in.getStringArrayList(STATE_LAYERS);pendingLayers=layers==null?Collections.emptyList():new ArrayList<>(layers);pendingNode=findNode(in.getString(STATE_NODE,""));pendingEntry=findNode(in.getString(STATE_ENTRY,""));pendingExit=findNode(in.getString(STATE_EXIT,""));pendingExitMode=in.getString(STATE_EXIT_MODE,"");if(pendingExitMode==null)pendingExitMode="";pendingStandardExit=findStandardExit(in.getString(STATE_STANDARD_EXIT,""));pendingExternalDirect=in.getBoolean(STATE_EXTERNAL_DIRECT,false);
        if("multihop".equals(pendingMode)&&(pendingEntry==null||pendingExit==null||pendingEntry.id.equals(pendingExit.id)||pendingExitMode.isEmpty())){clearPending();callback.finished(false,"Pending multihop permission state could not be restored safely; choose the hops again.");return;}
        if("external".equals(pendingMode)&&(pendingStandardExit==null||(!pendingExternalDirect&&pendingEntry==null))){clearPending();callback.finished(false,"Pending external Speed Lab path disappeared before Android VPN permission completed.");return;}
        if(!"multihop".equals(pendingMode)&&!"external".equals(pendingMode)&&in.containsKey(STATE_NODE)&&pendingNode==null){clearPending();callback.finished(false,"Pending test node disappeared before Android VPN permission completed.");return;}
        pendingCallback=callback;callback.progress("Waiting for Android VPN permission for restored "+displayMode(pendingMode)+" request…");
    }

    void disconnect(Callback callback) {
        clearPending();boolean wasMultihop=multihop.isActiveOrTransitioning();try{multihop.disconnect();}catch(Throwable ignored){}try{runtime.standardExit.disconnect();}catch(Throwable ignored){}
        orchestrator.disconnect(new AndroidModeOrchestrator.Callback(){@Override public void progress(String message){activity.runOnUiThread(()->callback.progress(message));}@Override public void finished(boolean success,String modeId,String message){activity.runOnUiThread(()->callback.finished(success,wasMultihop&&success?"Disconnected Android multihop and native Router VPN transports.":message));}});
    }

    boolean onActivityResult(int requestCode, int resultCode) { if(requestCode!=PREPARE_UNIFIED)return false;Callback cb=pendingCallback;if(resultCode!=Activity.RESULT_OK){clearPending();if(cb!=null)cb.finished(false,"Android VPN permission was not granted; Router VPN stayed disconnected.");return true;}startPending();return true; }

    private void requestPermission(String label) { Intent permission=VpnService.prepare(activity);if(permission==null){startPending();return;}if(pendingCallback!=null)pendingCallback.progress("Waiting for Android VPN permission for "+label+"…");activity.startActivityForResult(permission,PREPARE_UNIFIED); }

    private void startPending() {
        final String mode=pendingMode;final List<String>layers=new ArrayList<>(pendingLayers);final AndroidNodeStore.Node node=pendingNode,entry=pendingEntry,exit=pendingExit;final AndroidStandardExitStore.Entry standardExit=pendingStandardExit;final boolean externalDirect=pendingExternalDirect;final String exitMode=pendingExitMode;final Callback callback=pendingCallback;clearPending();if(callback==null)return;
        if("multihop".equals(mode)){if(entry==null||exit==null||entry.id.equals(exit.id)||exitMode.isEmpty()){callback.finished(false,"Multihop selection expired; choose entry and exit again.");return;}multihop.connect(entry,exit,exitMode,new AndroidMultihopRuntime.Callback(){@Override public void progress(String message){activity.runOnUiThread(()->callback.progress(message));}@Override public void finished(boolean ok,String message){activity.runOnUiThread(()->callback.finished(ok,message));}});return;}
        if("external".equals(mode)){if(standardExit==null||(!externalDirect&&entry==null)){callback.finished(false,"External test selection expired; choose the exit again.");return;}AndroidStandardExitRuntime.Callback bridge=new AndroidStandardExitRuntime.Callback(){@Override public void progress(String message){activity.runOnUiThread(()->callback.progress(message));}@Override public void finished(boolean ok,String message){activity.runOnUiThread(()->callback.finished(ok,message));}};if(externalDirect)runtime.standardExit.connectDirect(standardExit,bridge);else runtime.standardExit.connect(entry.file,standardExit,bridge);return;}
        final File bundle;try{bundle=node!=null?node.file:activeBundle();if(bundle==null||!bundle.isFile()||bundle.length()<=0)throw new IllegalStateException("Requested Router VPN node bundle is missing.");}catch(Exception error){callback.finished(false,safe(error));return;}
        AndroidModeOrchestrator.Callback bridge=new AndroidModeOrchestrator.Callback(){@Override public void progress(String message){activity.runOnUiThread(()->callback.progress(message));}@Override public void finished(boolean ok,String modeId,String message){activity.runOnUiThread(()->callback.finished(ok,message));}};
        if("smart-auto".equals(mode))orchestrator.auto(bundle,true,bridge);else if("auto".equals(mode))orchestrator.auto(bundle,false,bridge);else if("all".equals(mode))orchestrator.all(bundle,bridge);else if(mode.startsWith("custom:")){if(layers.isEmpty())callback.finished(false,"CUSTOM requires at least one saved layer.");else orchestrator.custom(bundle,layers,bridge);}else orchestrator.logical(bundle,mode,bridge);
    }

    private AndroidNodeStore.Node findNode(String id){if(id==null||id.isEmpty())return null;try{for(AndroidNodeStore.Node node:nodeStore.list())if(id.equals(node.id))return node;}catch(Exception ignored){}return null;}
    private AndroidStandardExitStore.Entry findStandardExit(String id){if(id==null||id.isEmpty())return null;try{return exitStore.get(id);}catch(Exception ignored){return null;}}
    private File activeBundle() throws Exception {String id=nodeStore.activeId();if(id==null||id.trim().isEmpty())throw new IllegalStateException("Pair/import and select a Router VPN node first.");File file=nodeStore.file(id);if(file==null||!file.isFile()||file.length()<=0)throw new IllegalStateException("Selected Router VPN node bundle is missing.");return file;}
    private void clearPending(){pendingMode="";pendingLayers=Collections.emptyList();pendingNode=null;pendingEntry=null;pendingExit=null;pendingStandardExit=null;pendingExternalDirect=false;pendingExitMode="";pendingCallback=null;}
    private static String displayMode(String mode){if("smart-auto".equals(mode))return"SMART AUTO";if("auto".equals(mode))return"AUTO";if("multihop".equals(mode))return"multihop";if("external".equals(mode))return"external exit";if(mode.startsWith("custom:"))return"CUSTOM";return mode.toUpperCase();}
    private static String safe(Throwable error){String value=error==null?"":error.getMessage();return value==null||value.trim().isEmpty()?"Router VPN connection error":value.trim();}
    @Override public void close(){clearPending();}
}
