#!/usr/bin/env python3
"""Run the production measurement lease, including concurrent acquisition."""
from pathlib import Path
import shutil
import subprocess
import tempfile
ROOT = Path(__file__).resolve().parent
HARNESS = r'''
package com.eabusham.routervpn;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
public class Main {
 public static void main(String[] args)throws Exception{
  Object first=AndroidMTUMeasurementGate.acquire();
  if(!AndroidMTUMeasurementGate.held())throw new AssertionError("lease absent");
  try{AndroidMTUMeasurementGate.acquire();throw new AssertionError("second lease accepted");}catch(IllegalStateException expected){}
  AtomicInteger starts=new AtomicInteger();
  try{AndroidMTUMeasurementGate.startMTU(starts::incrementAndGet);throw new AssertionError("test overlap accepted");}catch(IllegalStateException expected){}
  AndroidMTUMeasurementGate.release(new Object());
  if(!AndroidMTUMeasurementGate.held()||starts.get()!=0)throw new AssertionError("stale release changed ownership");
  AndroidMTUMeasurementGate.release(first);AndroidMTUMeasurementGate.startMTU(starts::incrementAndGet);
  if(starts.get()!=1)throw new AssertionError("valid MTU start not delivered");
  Object second=AndroidMTUMeasurementGate.acquire();AndroidMTUMeasurementGate.release(first);
  if(!AndroidMTUMeasurementGate.held())throw new AssertionError("old callback released new test");
  AndroidMTUMeasurementGate.release(second);
  CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);
  Thread mutation=new Thread(()->{try{AndroidMTUMeasurementGate.startMTU(()->{entered.countDown();release.await();});}catch(Exception e){throw new AssertionError(e);}});
  mutation.start();entered.await();
  AtomicInteger acquired=new AtomicInteger();
  Thread measurement=new Thread(()->{Object lease=AndroidMTUMeasurementGate.acquire();acquired.incrementAndGet();AndroidMTUMeasurementGate.release(lease);});
  measurement.start();Thread.sleep(25);
  if(acquired.get()!=0)throw new AssertionError("lease crossed in-flight MTU publication");
  release.countDown();mutation.join(3000);measurement.join(3000);
  if(mutation.isAlive()||measurement.isAlive()||acquired.get()!=1||AndroidMTUMeasurementGate.held())throw new AssertionError("lease did not drain");
  System.out.println("Android MTU/Speed Lab production lease: PASS");
 }
}
'''
def main():
    if not shutil.which('javac') or not shutil.which('java'): raise RuntimeError('JDK required')
    with tempfile.TemporaryDirectory(prefix='routervpn-mtu-gate-') as directory:
        root=Path(directory); (root/'Main.java').write_text(HARNESS)
        source=ROOT/'app/src/main/java/com/eabusham/routervpn/AndroidMTUMeasurementGate.java'
        subprocess.run(['javac','--release','17','-d',str(root),str(source),str(root/'Main.java')],check=True,timeout=30)
        subprocess.run(['java','-cp',str(root),'com.eabusham.routervpn.Main'],check=True,timeout=15)
if __name__=='__main__': main()
