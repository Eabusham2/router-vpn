#!/usr/bin/env python3
"""Exercise asynchronous stop acknowledgments without Android or network traffic."""
from pathlib import Path
import subprocess,tempfile,shutil
root=Path(__file__).resolve().parents[1]
source=root/'android/app/src/main/java/com/eabusham/routervpn/AndroidServiceStopConfirmation.java'
java_root = source.parent
# These checks tie the executable helper to the real service/controller boundary.
# A stop-intent enqueue is not an acknowledgment; service cleanup must return first.
for controller_name, service_name, key in (
    ("NativeSingBoxController.java", "LayeredVpnService.java", "STATE_KEY"),
    ("NativeXrayController.java", "XrayVpnService.java", "NativeXrayController.STATE_KEY"),
):
    controller = (java_root / controller_name).read_text()
    service = (java_root / service_name).read_text()
    start = controller.split("void start(SessionInfo session)", 1)[1].split("void stop()", 1)[0]
    stop = controller.split("void stop()", 1)[1].split("String getState()", 1)[0]
    state = controller.split("String getState()", 1)[1].split("String getMode()", 1)[0]
    assert "AndroidServiceStopConfirmation.start(STATE_KEY" in start
    assert "AndroidServiceStopConfirmation.request(STATE_KEY" in stop
    assert ".putExtra(AndroidServiceStopConfirmation.EXTRA_COMMAND, command)" in stop
    assert "AndroidServiceStopConfirmation.state(STATE_KEY" in state
    request = service.split("if (ACTION_STOP.equals(action)) {", 1)[1].split("return Service.START_NOT_STICKY;", 1)[0]
    assert "intent.getLongExtra(AndroidServiceStopConfirmation.EXTRA_COMMAND, 0L)" in request
    acknowledgment = f"AndroidServiceStopConfirmation.acknowledge({key}, command);"
    assert request.index('shutdown("DOWN", "");') < request.index(acknowledgment)
    assert "finally {" not in request
harness=r'''package com.eabusham.routervpn;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

public final class StopConfirmationTest {
    static void expect(boolean ok, String message) { if(!ok) throw new AssertionError(message); }
    static String state(String key, String value) { return AndroidServiceStopConfirmation.state(key,()->value); }
    static long request(String key) { AtomicLong token=new AtomicLong(); AndroidServiceStopConfirmation.request(key,token::set); return token.get(); }
    static void ack(String key,long token) { AndroidServiceStopConfirmation.acknowledge(key,token); }
    static void runChannel(String key,String other) throws Exception {
        for(String terminal:new String[]{"DOWN","FAILED","REVOKED"}) {
            long token=request(key);
            expect("STOPPING".equals(state(key,terminal)),"old "+terminal+" accepted as stop proof");
            AtomicInteger starts=new AtomicInteger();
            try {AndroidServiceStopConfirmation.start(key,starts::incrementAndGet);throw new AssertionError("start accepted while stop pending");}catch(IllegalStateException expected){}
            expect(starts.get()==0,"rejected start was dispatched");
            ack(key,0);expect("STOPPING".equals(state(key,terminal)),"untagged stop released ownership");
            ack(key,token);expect(terminal.equals(state(key,terminal)),"matching ack did not release state");
        }
        System.out.println("PASS "+key+" stale terminal states and start exclusion");
        long old=request(key),current=request(key);
        ack(key,old);expect("STOPPING".equals(state(key,"DOWN")),"old command acknowledged newer stop");
        ack(key,current);expect("DOWN".equals(state(key,"DOWN")),"new command could not finish");
        System.out.println("PASS "+key+" out-of-order stop acknowledgments");
        AtomicLong failed=new AtomicLong();
        try {AndroidServiceStopConfirmation.request(key,id->{failed.set(id);throw new IllegalStateException("dispatch failed");});throw new AssertionError("dispatch error swallowed");}catch(IllegalStateException expected){}
        expect("STOPPING".equals(state(key,"DOWN")),"failed dispatch released ownership");
        current=request(key);ack(key,failed.get());expect("STOPPING".equals(state(key,"DOWN")),"late failed dispatch ack released retry");ack(key,current);
        System.out.println("PASS "+key+" failed dispatch retains ownership until retry completes");
        long own=request(key),foreign=request(other);
        ack(other,own);expect("STOPPING".equals(state(other,"DOWN")),"cross-engine acknowledgment accepted");
        ack(key,own);expect("STOPPING".equals(state(other,"DOWN")),"one engine released the other");ack(other,foreign);
        System.out.println("PASS "+key+" engine-specific acknowledgment");
        CountDownLatch dispatchEntered=new CountDownLatch(1),releaseDispatch=new CountDownLatch(1),stopAttempting=new CountDownLatch(1),stopDispatched=new CountDownLatch(1);
        AtomicLong stop=new AtomicLong();AtomicReference<Throwable> failure=new AtomicReference<>();
        Thread starter=new Thread(()->{try {AndroidServiceStopConfirmation.start(key,()->{dispatchEntered.countDown();try{expect(releaseDispatch.await(3,TimeUnit.SECONDS),"start dispatch latch timed out");}catch(InterruptedException e){throw new RuntimeException(e);}});}catch(Throwable e){failure.set(e);}});
        Thread stopper=new Thread(()->{stopAttempting.countDown();try{AndroidServiceStopConfirmation.request(key,id->{stop.set(id);stopDispatched.countDown();});}catch(Throwable e){failure.set(e);}});
        starter.start();expect(dispatchEntered.await(3,TimeUnit.SECONDS),"start did not dispatch");stopper.start();expect(stopAttempting.await(3,TimeUnit.SECONDS),"stop did not attempt");
        try {expect(!stopDispatched.await(80,TimeUnit.MILLISECONDS),"stop overtook start dispatch");}finally{releaseDispatch.countDown();}
        starter.join(3000);stopper.join(3000);expect(!starter.isAlive()&&!stopper.isAlive(),"dispatch threads hung");if(failure.get()!=null)throw new AssertionError(failure.get());
        expect("STOPPING".equals(state(key,"DOWN")),"queued stop accepted old DOWN");ack(key,stop.get());
        System.out.println("PASS "+key+" dispatch ordering across threads");
    }
    public static void main(String[] args) throws Exception {
        runChannel("layered_state_v1","xray_state_v1");runChannel("xray_state_v1","layered_state_v1");
        try{request("unknown");throw new AssertionError("unknown channel accepted");}catch(IllegalArgumentException expected){}
        System.out.println("PASS unknown service channel rejected");
        System.out.println("Android service stop command acknowledgment: PASS");
    }
}'''
with tempfile.TemporaryDirectory(prefix='rvpn-stop-confirm-') as temp:
    base=Path(temp);pkg=base/'com/eabusham/routervpn';pkg.mkdir(parents=True)
    shutil.copyfile(source,pkg/source.name)
    (pkg/'StopConfirmationTest.java').write_text(harness)
    subprocess.run(['javac','-d',str(base),str(pkg/source.name),str(pkg/'StopConfirmationTest.java')],check=True,timeout=30)
    subprocess.run(['java','-cp',str(base),'com.eabusham.routervpn.StopConfirmationTest'],check=True,timeout=30)
