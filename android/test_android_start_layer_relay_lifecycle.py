#!/usr/bin/env python3
"""Run the shipping Android XOR relay with real local TCP/UDP and owned close.

Only VpnService protection and Android Base64 are boundary doubles. The local
upstream is injected through the private constructor; production metadata still
rejects loopback/hostnames and never uses a resolver.
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
JAVA=ROOT/'android/app/src/main/java/com/eabusham/routervpn'
APP='com/eabusham/routervpn/'
HARNESS=r'''package com.eabusham.routervpn;
import android.net.VpnService;import java.io.*;import java.net.*;import java.nio.file.*;import java.lang.reflect.*;import java.util.*;import java.util.concurrent.*;import java.util.concurrent.atomic.*;import org.json.*;
public final class RelayLifetimeHarness {
 static int checks;static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
 interface Attempt{void run()throws Exception;}static void reject(Attempt task,String message)throws Exception{boolean rejected=false;try{task.run();}catch(Exception expected){rejected=true;}check(rejected,message);}
 static Object field(Object object,String name)throws Exception{Field f=object.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(object);}
 static byte[] key(){byte[] key=new byte[32];Arrays.fill(key,(byte)0x35);return key;}
 static boolean erased(AndroidStartLayerRelay relay)throws Exception{for(byte b:(byte[])field(relay,"key"))if(b!=0)return false;return true;}
 static void joined(AndroidStartLayerRelay relay)throws Exception{check(((ExecutorService)field(relay,"workers")).isTerminated(),"relay returned before actual worker completion");check(((Set<?>)field(relay,"tcpSockets")).isEmpty()&&((Set<?>)field(relay,"udpSockets")).isEmpty(),"relay forgot an owned socket");check(erased(relay),"quiescent relay did not clear its key");}
 static final class Protector extends VpnService implements AndroidStartLayerRelay.SocketProtector {
  final AtomicInteger tcp=new AtomicInteger(),udp=new AtomicInteger();volatile String blocked="";final CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);
  void protect(String kind){if(blocked.equals(kind)){entered.countDown();boolean interrupted=false;for(;;){try{release.await();break;}catch(InterruptedException e){interrupted=true;}}if(interrupted)Thread.currentThread().interrupt();}}
  public void protectRelaySocket(Socket socket){tcp.incrementAndGet();protect("tcp");}
  public void protectRelaySocket(DatagramSocket socket){udp.incrementAndGet();protect("udp");}
 }
 static AndroidStartLayerRelay relay(Protector protector)throws Exception{
  Class<?> metadata=Class.forName("com.eabusham.routervpn.AndroidStartLayerRelay$Metadata");Constructor<?> data=metadata.getDeclaredConstructor(InetAddress.class,byte[].class);data.setAccessible(true);
  Constructor<AndroidStartLayerRelay> create=AndroidStartLayerRelay.class.getDeclaredConstructor(VpnService.class,AndroidStartLayerRelay.FatalHandler.class,metadata);create.setAccessible(true);
  return create.newInstance(protector,(AndroidStartLayerRelay.FatalHandler)(message)->{},data.newInstance(InetAddress.getByAddress(new byte[]{127,0,0,1}),key()));
 }
 static ServerSocket remote()throws Exception{ServerSocket server=new ServerSocket();server.setReuseAddress(true);server.bind(new InetSocketAddress("127.0.0.1",AndroidStartLayerRelay.SERVER_PORT));server.setSoTimeout(2000);return server;}
 static Socket client()throws Exception{Socket client=new Socket();client.connect(new InetSocketAddress("127.0.0.1",AndroidStartLayerRelay.LISTEN_PORT),1000);client.setSoTimeout(2000);return client;}
 static byte[] xor(byte[] bytes){byte[] result=bytes.clone();for(int i=0;i<result.length;i++)result[i]^=0x35;return result;}
 static void traffic()throws Exception{
  for(int generation=0;generation<3;generation++){
   Protector owner=new Protector();AndroidStartLayerRelay relay=relay(owner);
   try(ServerSocket upstream=remote();DatagramSocket udpUpstream=new DatagramSocket(new InetSocketAddress("127.0.0.1",AndroidStartLayerRelay.SERVER_PORT))){
    udpUpstream.setSoTimeout(2000);relay.start();
    try(Socket local=client();Socket network=upstream.accept();DatagramSocket udpLocal=new DatagramSocket()){
     network.setSoTimeout(2000);byte[] payload=("owned-ciphertext-"+generation).getBytes(java.nio.charset.StandardCharsets.US_ASCII);
     local.getOutputStream().write(payload);local.getOutputStream().flush();check(Arrays.equals(network.getInputStream().readNBytes(payload.length),xor(payload)),"TCP whitening changed captured ciphertext");
     network.getOutputStream().write(xor(payload));network.getOutputStream().flush();check(Arrays.equals(local.getInputStream().readNBytes(payload.length),payload),"TCP return path changed ciphertext");
     udpLocal.setSoTimeout(2000);udpLocal.send(new DatagramPacket(payload,payload.length,new InetSocketAddress("127.0.0.1",AndroidStartLayerRelay.LISTEN_PORT)));
     DatagramPacket received=new DatagramPacket(new byte[128],128);udpUpstream.receive(received);check(Arrays.equals(Arrays.copyOf(received.getData(),received.getLength()),xor(payload)),"UDP whitening changed datagram");
     byte[] reply=xor(payload);udpUpstream.send(new DatagramPacket(reply,reply.length,received.getSocketAddress()));DatagramPacket returned=new DatagramPacket(new byte[128],128);udpLocal.receive(returned);check(Arrays.equals(Arrays.copyOf(returned.getData(),returned.getLength()),payload),"UDP return path changed datagram");
     check(owner.tcp.get()==1&&owner.udp.get()==1,"relay bypassed captured socket protection");
     relay.close();joined(relay);check(network.getInputStream().read()==-1,"TCP lower socket survived close");check(local.getInputStream().read()==-1,"TCP app socket survived close");relay.close();joined(relay);
    }
   }finally{relay.close();}
  }
 }
 static void retainedProtection()throws Exception{
  for(String protocol:new String[]{"tcp","udp"}){
   Protector owner=new Protector();owner.blocked=protocol;AndroidStartLayerRelay relay=relay(owner);
   try(ServerSocket upstream=remote();DatagramSocket udpLocal=new DatagramSocket()){
    relay.start();Socket local=null;
    try{
     if(protocol.equals("tcp"))local=client();else udpLocal.send(new DatagramPacket(new byte[]{1},1,new InetSocketAddress("127.0.0.1",AndroidStartLayerRelay.LISTEN_PORT)));
     check(owner.entered.await(2,TimeUnit.SECONDS),"captured protection callback was not admitted");
     long start=System.nanoTime();reject(relay::close,"unfinished protection worker was acknowledged as closed");check(System.nanoTime()-start<TimeUnit.SECONDS.toNanos(3),"close exceeded its bound");
     check(!erased(relay),"key was cleared while a captured worker was still active");check(!((ExecutorService)field(relay,"workers")).isTerminated(),"late worker was falsely joined");
    }finally{owner.release.countDown();relay.close();if(local!=null)local.close();}
    joined(relay);upstream.setSoTimeout(200);try{Socket late=upstream.accept();late.close();throw new AssertionError("late callback created a network connection");}catch(SocketTimeoutException expected){checks++;}
   }finally{owner.release.countDown();relay.close();}
  }
 }
 static final class FailingSocket extends Socket {boolean fail=true;@Override public synchronized void close()throws IOException{if(fail)throw new IOException("private credential must not escape");super.close();}}
 @SuppressWarnings("unchecked")static void retainedCloseError()throws Exception{
  AndroidStartLayerRelay relay=relay(new Protector());FailingSocket socket=new FailingSocket();((Set<Socket>)field(relay,"tcpSockets")).add(socket);
  try{relay.close();throw new AssertionError("unconfirmed socket close was forgotten");}catch(IllegalStateException expected){check(!expected.getMessage().contains("credential"),"close exposed a lower error");}
  check(!erased(relay)&&((Set<?>)field(relay,"tcpSockets")).contains(socket),"failed close lost its resource owner");socket.fail=false;relay.close();joined(relay);
 }
 static void partialStartup()throws Exception{
  AndroidStartLayerRelay relay=relay(new Protector());try(DatagramSocket conflict=new DatagramSocket(new InetSocketAddress("127.0.0.1",AndroidStartLayerRelay.LISTEN_PORT))){reject(relay::start,"occupied UDP listener was accepted");relay.close();joined(relay);}
  reject(relay::start,"closed relay reopened its sockets");
 }
 static void metadata()throws Exception{
  Path dir=Files.createTempDirectory("relay-owned-metadata-");Path file=dir.resolve(AndroidStartLayerRelay.SESSION_FILE);Protector protector=new Protector();
  JSONObject metadata=new JSONObject().put("version",1).put("listen_port",AndroidStartLayerRelay.LISTEN_PORT).put("target_port",AndroidStartLayerRelay.SERVER_PORT).put("key_b64",Base64.getEncoder().encodeToString(key()));
  try{
   for(String host:new String[]{"must-not-resolve.invalid","localhost","127.0.0.1","127.0.0.2","::1","0.0.0.0","224.0.0.1"}){metadata.put("target_host",host);Files.writeString(file,metadata.toString());reject(()->AndroidStartLayerRelay.prepareIfConfigured(protector,dir.toFile(),message->{}),"unsafe or unresolved target accepted: "+host);}
   metadata.put("target_host","203.0.113.10");Files.writeString(file,metadata.toString());AndroidStartLayerRelay prepared=AndroidStartLayerRelay.prepareIfConfigured(protector,dir.toFile(),message->{});
   check(field(prepared,"tcpListener")==null&&field(prepared,"udpListener")==null&&protector.tcp.get()==0&&protector.udp.get()==0,"preparation started an unowned listener");prepared.close();joined(prepared);
  }finally{Files.deleteIfExists(file);Files.deleteIfExists(dir);}
 }
 public static void main(String[] args)throws Exception{metadata();traffic();retainedProtection();retainedCloseError();partialStartup();System.out.println("Android real XOR relay lifetime: PASS "+checks+" checks (real TCP/UDP; OS protection doubled)");}
}'''


def replaced_method(source,signature,replacement):
    start=source.index(signature);opening=source.index('{',start);depth=1;end=opening+1
    while depth:
        depth+=(source[end]=='{')-(source[end]=='}');end+=1
    return source[:start]+replacement+source[end:]


def main():
    jar=Path(os.environ.get('ANDROID_JSON_JAR','/usr/share/java/com.android.json.jar'))
    if not jar.is_file():raise SystemExit('Real Android JSON JAR is required for the relay lifecycle fixture')
    source=(JAVA/'AndroidStartLayerRelay.java').read_text()
    with tempfile.TemporaryDirectory(prefix='routervpn-android-relay-life-') as temporary:
        root=Path(temporary)
        files={APP+'AndroidStartLayerRelay.java':source,APP+'AndroidNumericAddress.java':(JAVA/'AndroidNumericAddress.java').read_text(),APP+'RelayLifetimeHarness.java':HARNESS,
               'android/net/VpnService.java':'package android.net; public class VpnService {public boolean protect(java.net.Socket s){return true;}public boolean protect(java.net.DatagramSocket s){return true;}}',
               'android/util/Base64.java':'package android.util;public class Base64{public static final int DEFAULT=0;public static byte[] decode(String s,int flags){return java.util.Base64.getDecoder().decode(s);}}'}
        for relative,data in files.items():target=root/relative;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(data)
        command=[shutil.which('javac') or 'javac','-cp',str(jar),'-d',str(root/'classes'),*[str(root/path) for path in files]]
        subprocess.run(command,check=True,timeout=30)
        run=[shutil.which('java') or 'java','-cp',str(root/'classes')+os.pathsep+str(jar),'com.eabusham.routervpn.RelayLifetimeHarness']
        subprocess.run(run,check=True,timeout=25)
        old_close='''@Override public synchronized void close(){if(!closed.compareAndSet(false,true))return;try{if(tcpListener!=null)tcpListener.close();}catch(Exception ignored){}if(udpListener!=null)udpListener.close();for(UdpSession session:udpSessions.values())session.upstream.close();udpSessions.clear();workers.shutdownNow();Arrays.fill(key,(byte)0);}'''
        (root/(APP+'AndroidStartLayerRelay.java')).write_text(replaced_method(source,'@Override public synchronized void close()',old_close))
        subprocess.run(command,check=True,timeout=30)
        negative=subprocess.run(run,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=25)
        if negative.returncode==0:raise AssertionError('Legacy unjoined relay close passed the actual lifetime fixture')
        if 'AssertionError' not in negative.stdout:raise AssertionError('Relay negative control failed outside its ownership assertions: '+negative.stdout[-2000:])
        print('Android XOR relay negative control: legacy unjoined close rejected')


if __name__=='__main__':main()
