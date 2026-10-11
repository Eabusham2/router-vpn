package com.eabusham.routervpn;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import io.nekohasekai.libbox.Libbox;
import io.nekohasekai.libbox.RouterPQEvent;
import io.nekohasekai.libbox.RouterPQFactory;
import io.nekohasekai.libbox.RouterPQProtocol;

/** Packet-only Rust host. It cannot select a socket, resolver, VPN or peer. */
final class RouterPQNative implements RouterPQFactory {
    private static boolean installed;
    static synchronized void install() throws Exception {
        if (installed) return;
        System.loadLibrary("routervpn_rosenpass_jni");
        if (nativeABI()!=1) throw new IOException("Native PQ ABI mismatch");
        Libbox.routerInstallPQFactory(new RouterPQNative());
        installed=true;
    }
    @Override public RouterPQProtocol createProtocol(byte[] secretKey, byte[] publicKey, byte[] peerKey, int version) throws Exception {
        return new Protocol(nativeOpen(secretKey,publicKey,peerKey,version));
    }
    private static native int nativeABI();
    private static native long nativeOpen(byte[] secretKey,byte[] publicKey,byte[] peerKey,int version) throws IOException;
    private static native byte[] nativeEvent(long handle,int kind,byte[] packet) throws IOException;
    private static native void nativeClose(long handle) throws IOException;

    static RouterPQEvent decode(byte[] data) throws IOException {
        if (data==null) throw new IOException("Missing native PQ event");
        try {
            if (data.length<44 || data.length>65579) throw new IOException("Invalid native PQ event size");
            ByteBuffer b=ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
            int status=b.getInt(), wait=b.getInt(), flags=b.getInt();
            if ((status!=0 && status!=-2) || wait<0 || wait>1000 || (flags&~3)!=0 || flags==3 ||
                (status==-2 && (flags!=0 || data.length!=44))) throw new IOException("Invalid native PQ event policy");
            if ((flags&1)==0) for(int i=12;i<44;i++) if(data[i]!=0) throw new IOException("Unexpected native PQ key");
            RouterPQEvent event=new RouterPQEvent();
            event.setWaitMilliseconds(wait);event.setRejected(status==-2);event.setExpired((flags&2)!=0);
            event.setPacket(Arrays.copyOfRange(data,44,data.length));
            if ((flags&1)!=0) {
                byte[] key=Arrays.copyOfRange(data,12,44);
                try { event.setKey(key); } finally { Arrays.fill(key,(byte)0); }
            }
            return event;
        } finally { Arrays.fill(data,(byte)0); }
    }
    private static final class Protocol implements RouterPQProtocol {
        private long handle;
        private IOException closeError;
        Protocol(long value) throws IOException {
            if(value<=0) throw new IOException("Missing native PQ owner");handle=value;
        }
        @Override public synchronized RouterPQEvent processEvent(int kind,byte[] packet) throws Exception {
            if(handle==0) throw new IOException("Native PQ owner is closed");
            return decode(nativeEvent(handle,kind,packet));
        }
        @Override public synchronized void stop() throws Exception {
            long captured=handle;handle=0;
            if(captured!=0) try { nativeClose(captured); } catch(IOException e) { closeError=new IOException("Native PQ cleanup failed"); }
            if(closeError!=null) throw closeError;
        }
    }
}
