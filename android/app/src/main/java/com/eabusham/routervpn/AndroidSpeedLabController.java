package com.eabusham.routervpn;

import android.app.Activity;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;

/** Connect-test-disconnect transaction for the native Android Speed Lab. */
final class AndroidSpeedLabController {
    interface Callback { void progress(String message); void finished(AndroidSpeedLab.Result result, Throwable error); }

    static final class Request {
        String scope="current", topology="router", mode="smart-auto", exitMode="shadowsocks", durationMode="auto";
        AndroidNodeStore.Node node,entry,exit;
        AndroidStandardExitStore.Entry standardExit;
        List<String> customLayers=Collections.emptyList();
        double minSeconds=4,maxSeconds=12;
        boolean externalDirect=true;
    }

    private final Activity activity;
    private final AndroidUnifiedConnectionController connection;
    private final AndroidSpeedLab meter;
    private final AtomicBoolean running=new AtomicBoolean(false);

    AndroidSpeedLabController(Activity activity,AndroidUnifiedConnectionController connection){this.activity=activity;this.connection=connection;this.meter=new AndroidSpeedLab(activity);}
    boolean isRunning(){return running.get();}

    void run(Request request,Callback callback){
        if(request==null){callback.finished(null,new IllegalArgumentException("Speed Lab request is required."));return;}
        if(!running.compareAndSet(false,true)){callback.finished(null,new IllegalStateException("Another Speed Lab test is already running."));return;}
        try{
            String scope=normalize(request.scope,"current");
            if("current".equals(scope)){callback.progress("Testing the actual current Android path…");measure(request,callback,false);return;}
            if(!"temporary".equals(scope)){finish(callback,null,new IllegalArgumentException("Speed Lab scope must be current or temporary."));return;}
            if(connection.isActiveOrTransitioning()){finish(callback,null,new IllegalStateException("Disconnect Router VPN before a temporary Android Speed Lab configuration."));return;}
            String topology=normalize(request.topology,"router");
            if("system-direct".equals(topology)){callback.progress("Testing raw Android system Internet with Router VPN disconnected…");measure(request,callback,false);return;}
            AndroidUnifiedConnectionController.Callback bridge=new AndroidUnifiedConnectionController.Callback(){
                @Override public void progress(String message){callback.progress(message);}
                @Override public void finished(boolean ok,String message){
                    if(!ok){finish(callback,null,new IllegalStateException(message));return;}
                    callback.progress("Temporary path is proven. Running Speed Lab without saving this graph…");
                    measure(request,callback,true);
                }
            };
            switch(topology){
                case "router":
                    if(request.node==null){finish(callback,null,new IllegalArgumentException("Choose a Router VPN node."));return;}
                    String mode=normalize(request.mode,"smart-auto");List<String>layers=request.customLayers==null?Collections.emptyList():new ArrayList<>(request.customLayers);if("custom".equals(mode))mode="custom:speed-lab";
                    connection.connectNode(request.node,mode,layers,bridge);break;
                case "multihop":
                    if(request.entry==null||request.exit==null||request.entry.id.equals(request.exit.id)){finish(callback,null,new IllegalArgumentException("Choose different Router VPN entry and exit nodes."));return;}
                    connection.connectMultihop(request.entry,request.exit,normalize(request.exitMode,"shadowsocks"),bridge);break;
                case "external":
                    if(request.standardExit==null){finish(callback,null,new IllegalArgumentException("Choose a stored custom exit."));return;}
                    connection.connectExternal(request.entry,request.standardExit,request.externalDirect,bridge);break;
                default: finish(callback,null,new IllegalArgumentException("Unsupported Android Speed Lab topology: "+topology));
            }
        }catch(Throwable error){finish(callback,null,error);}
    }

    private void measure(Request request,Callback callback,boolean cleanup){
        meter.run(request.durationMode,request.minSeconds,request.maxSeconds,(result,error)->activity.runOnUiThread(()->{
            if(!cleanup){finish(callback,result,error);return;}
            callback.progress(error==null?"Measurement complete. Tearing down temporary path…":"Measurement failed. Tearing down temporary path…");
            connection.disconnect(new AndroidUnifiedConnectionController.Callback(){
                @Override public void progress(String message){callback.progress(message);}
                @Override public void finished(boolean ok,String message){
                    Throwable finalError=error;
                    if(!ok){IllegalStateException cleanupError=new IllegalStateException("Temporary Android path cleanup failed: "+message);if(finalError!=null)cleanupError.addSuppressed(finalError);finalError=cleanupError;}
                    finish(callback,result,finalError);
                }
            });
        }));
    }

    private void finish(Callback callback,AndroidSpeedLab.Result result,Throwable error){running.set(false);callback.finished(result,error);}
    private static String normalize(String value,String fallback){String out=value==null?"":value.trim().toLowerCase(Locale.US);return out.isEmpty()?fallback:out;}
}
