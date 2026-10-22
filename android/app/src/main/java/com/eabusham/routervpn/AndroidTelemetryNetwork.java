package com.eabusham.routervpn;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.VpnService;
import android.os.Build;
import android.os.Process;

import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/** A retained native owner plus one exact Android Network, on every supported API. */
final class AndroidTelemetryNetwork {
    interface Check { void run() throws Exception; }
    final Network network;
    final String interfaceName;
    private final Context context;
    private final ConnectivityManager connectivity;
    private final Check owner;
    private final boolean vpn;
    private final String links, physical;

    private AndroidTelemetryNetwork(Context context, Network network, boolean vpn, Check owner) throws Exception {
        this.context=context.getApplicationContext();
        this.connectivity=(ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE);
        this.network=network;this.vpn=vpn;this.owner=owner;
        LinkProperties value=connectivity.getLinkProperties(network);
        if(value==null||value.getInterfaceName()==null)throw new IllegalStateException("The captured network has no live interface.");
        interfaceName=value.getInterfaceName();links=linkIdentity(value);physical=physicalIdentity(connectivity);
        check();
    }

    static AndroidTelemetryNetwork direct(Context context) throws Exception {
        ConnectivityManager cm=(ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE);
        Network active=cm==null?null:cm.getActiveNetwork();
        NetworkCapabilities caps=active==null?null:cm.getNetworkCapabilities(active);
        if(caps==null||caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)||AndroidVpnMutationGuard.isBusy(context))
            throw new IllegalStateException("Disconnect the VPN before measuring direct node latency; routed RTT is never saved as a direct benchmark.");
        return new AndroidTelemetryNetwork(context,active,false,()->{
            if(AndroidVpnMutationGuard.isBusy(context))throw new IllegalStateException("A VPN operation replaced the captured direct path.");
        });
    }

    static AndroidTelemetryNetwork named(Context context,String name,Check owner) throws Exception {
        if(name==null||name.isEmpty()||owner==null)throw new IllegalStateException("The native tunnel has no retained interface owner.");
        owner.run();
        ConnectivityManager cm=(ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE);
        Network found=null;
        for(Network candidate:cm.getAllNetworks()){
            NetworkCapabilities caps=cm.getNetworkCapabilities(candidate);LinkProperties lp=cm.getLinkProperties(candidate);
            if(caps==null||lp==null||!caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)||!name.equals(lp.getInterfaceName()))continue;
            if(found!=null)throw new IllegalStateException("More than one VPN network claims the retained tunnel interface.");
            found=candidate;
        }
        if(found==null)throw new IllegalStateException("The retained native tunnel has no matching Android VPN network.");
        return new AndroidTelemetryNetwork(context,found,true,owner);
    }

    static AndroidTelemetryNetwork addressed(Context context,Collection<String> addresses,Check owner) throws Exception {
        if(addresses==null||addresses.isEmpty()||owner==null)throw new IllegalStateException("Native tunnel address readback is unavailable.");
        owner.run();
        Set<String> expected=new HashSet<>();
        for(String address:addresses)expected.add(new LinkAddress(address).toString());
        ConnectivityManager cm=(ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE);
        String found=null;
        for(Network candidate:cm.getAllNetworks()){
            NetworkCapabilities caps=cm.getNetworkCapabilities(candidate);LinkProperties lp=cm.getLinkProperties(candidate);
            if(caps==null||lp==null||!caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN))continue;
            Set<String> actual=new HashSet<>();for(LinkAddress address:lp.getLinkAddresses())actual.add(address.toString());
            if(!actual.equals(expected))continue;
            if(found!=null)throw new IllegalStateException("Native tunnel addresses match more than one VPN interface.");
            found=lp.getInterfaceName();
        }
        if(found==null)throw new IllegalStateException("Native tunnel addresses do not match a live VPN interface.");
        return named(context,found,owner);
    }

    void check() throws Exception {
        owner.run();
        Network active=connectivity.getActiveNetwork();NetworkCapabilities caps=connectivity.getNetworkCapabilities(network);
        LinkProperties current=connectivity.getLinkProperties(network);
        if(active==null||!network.equals(active)||caps==null||caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)!=vpn
                ||current==null||!links.equals(linkIdentity(current))||!physical.equals(physicalIdentity(connectivity)))
            throw new IllegalStateException("The captured Android network or physical path changed; telemetry was discarded.");
        if(vpn){
            if(VpnService.prepare(context)!=null)throw new IllegalStateException("Android VPN ownership was revoked.");
            if(Build.VERSION.SDK_INT>=Build.VERSION_CODES.R&&caps.getOwnerUid()!=Process.myUid())
                throw new IllegalStateException("The VPN network belongs to another application.");
            NetworkInterface actual=NetworkInterface.getByName(interfaceName);
            if(actual==null||!actual.isUp())throw new IllegalStateException("The retained native VPN interface is no longer up.");
        }
        owner.run();
    }

    String pathIdentity(){return network.getNetworkHandle()+":"+interfaceName+":"+physical;}
    AndroidTelemetryNetwork retaining(Check extra)throws Exception{return new AndroidTelemetryNetwork(context,network,vpn,()->{owner.run();extra.run();});}
    private static String linkIdentity(LinkProperties value){
        ArrayList<String> addresses=new ArrayList<>();for(Object address:value.getLinkAddresses())addresses.add(address.toString());Collections.sort(addresses);
        return value.getInterfaceName()+":"+addresses+":"+value.getRoutes()+":"+value.getDnsServers()+":"+value.getMtu();
    }
    private static String physicalIdentity(ConnectivityManager connectivity) throws Exception {
        ArrayList<String> values=new ArrayList<>();
        for(Network network:connectivity.getAllNetworks()){
            NetworkCapabilities caps=connectivity.getNetworkCapabilities(network);LinkProperties links=connectivity.getLinkProperties(network);
            if(caps==null||links==null||caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN))continue;
            values.add(network.getNetworkHandle()+":"+linkIdentity(links)+":"+caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)+":"+caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)+":"+caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET));
        }
        if(values.isEmpty())throw new IllegalStateException("The current physical network cannot be captured.");
        Collections.sort(values);return digest(values.toString().getBytes(StandardCharsets.UTF_8));
    }
    static String digest(byte[] bytes) throws Exception {
        byte[] sum=MessageDigest.getInstance("SHA-256").digest(bytes);StringBuilder out=new StringBuilder(64);
        for(byte b:sum)out.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return out.toString();
    }
}
