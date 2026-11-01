package com.eabusham.routervpn;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/** One immutable physical cohort across temporary VPN/service generations.
 * Full copied link properties protect route/DNS/MTU identity. The published
 * measurement hash retains its existing projection; it is not the batch gate.
 * Callback payloads are used directly, without synchronous CM lookups. */
final class AndroidExternalComparisonNetwork implements AutoCloseable {
    private final ConnectivityManager manager;
    private final Map<Network,LinkProperties> links;
    private final Map<Network,String> transports;
    private final String identity;
    private Network physical,announcedDefault;
    private boolean changed,closed,registered,defaultRegistered;
    private final ConnectivityManager.NetworkCallback callback=new ConnectivityManager.NetworkCallback(){
        @Override public void onAvailable(Network network){synchronized(AndroidExternalComparisonNetwork.this){if(!closed&&!links.containsKey(network))changed=true;}}
        @Override public void onLost(Network network){synchronized(AndroidExternalComparisonNetwork.this){if(!closed)changed=true;}}
        @Override public void onLinkPropertiesChanged(Network network,LinkProperties value){synchronized(AndroidExternalComparisonNetwork.this){if(!closed&&!java.util.Objects.equals(links.get(network),value))changed=true;}}
        @Override public void onCapabilitiesChanged(Network network,NetworkCapabilities value){synchronized(AndroidExternalComparisonNetwork.this){if(!closed&&!java.util.Objects.equals(transports.get(network),transport(value)))changed=true;}}
    };
    private final ConnectivityManager.NetworkCallback defaults=new ConnectivityManager.NetworkCallback(){
        @Override public void onAvailable(Network network){synchronized(AndroidExternalComparisonNetwork.this){if(!closed){announcedDefault=network;if(links.containsKey(network))observePhysical(network);}}}
        @Override public void onCapabilitiesChanged(Network network,NetworkCapabilities value){synchronized(AndroidExternalComparisonNetwork.this){if(!closed&&network.equals(announcedDefault)&&value!=null&&!value.hasTransport(NetworkCapabilities.TRANSPORT_VPN))observePhysical(network);}}
        // An owned VPN becoming default removes the physical default, while its
        // sockets remain bound to that same Network. Actual loss is observed by
        // the independent NOT_VPN callback above.
    };
    private static final class Snapshot {
        final Map<Network,LinkProperties> links=new LinkedHashMap<>();
        final Map<Network,String> transports=new LinkedHashMap<>();
    }
    AndroidExternalComparisonNetwork(Context context)throws Exception{
        manager=(ConnectivityManager)context.getApplicationContext().getSystemService(Context.CONNECTIVITY_SERVICE);
        if(manager==null)throw new IllegalStateException("Physical-network ownership is unavailable.");
        Snapshot initial=snapshot();links=initial.links;transports=initial.transports;
        if(links.isEmpty())throw new IllegalStateException("Connect a physical network before comparing external paths.");
        identity=identity(links);checkDefault(false);
    }
    synchronized void start()throws Exception{
        if(closed||registered||defaultRegistered)throw new IllegalStateException("The network observer cannot be replaced.");
        manager.registerNetworkCallback(new NetworkRequest.Builder().clearCapabilities().addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(),callback);registered=true;
        manager.registerDefaultNetworkCallback(defaults);defaultRegistered=true;
        requireCurrent();
    }
    synchronized void requireCurrent()throws Exception{
        if(closed||changed)throw changed();
        Snapshot now=snapshot();
        if(!links.equals(now.links)||!transports.equals(now.transports)){changed=true;throw changed();}
        checkDefault(false);if(changed)throw changed();
    }
    /** The first trial reaches this only after the exact original VPN drains.
     * Before any trial starts, latch its actual physical default; never rebase. */
    synchronized void requireBeforeStart()throws Exception{requireCurrent();checkDefault(true);if(physical==null||changed)throw changed();}
    synchronized void requireProved(Network actual)throws Exception{requireCurrent();if(physical==null||actual==null||!physical.equals(actual)){changed=true;throw changed();}}
    synchronized void invalidate(){changed=true;}
    synchronized String identity()throws Exception{requireCurrent();return identity;}
    @Override public synchronized void close(){
        closed=true;RuntimeException error=null;
        if(registered)try{manager.unregisterNetworkCallback(callback);registered=false;}catch(RuntimeException failure){error=failure;}
        if(defaultRegistered)try{manager.unregisterNetworkCallback(defaults);defaultRegistered=false;}catch(RuntimeException failure){if(error==null)error=failure;else error.addSuppressed(failure);}
        if(error!=null)throw error;
    }
    private void observePhysical(Network network){if(!links.containsKey(network)||physical!=null&&!physical.equals(network))changed=true;else if(physical==null)physical=network;}
    private void checkDefault(boolean mustBePhysical){
        Network active=manager.getActiveNetwork();NetworkCapabilities caps=active==null?null:manager.getNetworkCapabilities(active);
        if(caps==null){changed=true;return;}
        if(caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)){if(mustBePhysical)changed=true;return;}
        observePhysical(active);
    }
    private Snapshot snapshot(){
        Snapshot result=new Snapshot();Network[] networks=manager.getAllNetworks();if(networks==null)throw new IllegalStateException("Physical network inventory is unavailable.");
        for(Network network:networks){
            NetworkCapabilities caps=manager.getNetworkCapabilities(network);LinkProperties value=manager.getLinkProperties(network);
            if(caps==null)throw new IllegalStateException("A network changed during cohort capture.");
            if(caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN))continue;
            if(value==null||value.getInterfaceName()==null)throw new IllegalStateException("A physical network has incomplete link identity.");
            result.links.put(network,new LinkProperties(value));result.transports.put(network,transport(caps));
        }
        return result;
    }
    private static String transport(NetworkCapabilities caps){
        if(caps==null||caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN))return null;
        return caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)+":"+caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)+":"+
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)+":"+caps.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH)+":"+
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)+":"+caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED);
    }
    private static String identity(Map<Network,LinkProperties> values)throws Exception{
        ArrayList<String> sorted=new ArrayList<>();for(Map.Entry<Network,LinkProperties> entry:values.entrySet())sorted.add(entry.getKey().toString()+":"+entry.getValue().getInterfaceName()+":"+entry.getValue().getLinkAddresses());Collections.sort(sorted);
        return AndroidTorProfile.digest(sorted.toString().getBytes(StandardCharsets.UTF_8));
    }
    private static IllegalStateException changed(){return new IllegalStateException("The physical route, default network or link policy changed; retest the complete external cohort.");}
}
