package com.eabusham.routervpn;

/** Process-owned exclusion between TUN mutation and a Speed Lab transaction.
 * The opaque lease survives temporary VPN generations but not process death.
 * Stale callbacks cannot release a newer lease. No timer can reopen a VPN. */
final class AndroidMTUMeasurementGate {
    interface Start { void run() throws Exception; }
    private static Object active;
    private AndroidMTUMeasurementGate() {}
    static synchronized Object acquire() {
        if (active != null) throw new IllegalStateException("Another Speed Lab transaction owns MTU measurement.");
        active = new Object(); return active;
    }
    static synchronized boolean held() { return active != null; }
    static synchronized void release(Object lease) { if (lease != null && active == lease) active = null; }
    static synchronized void startMTU(Start operation) throws Exception {
        if (active != null) throw new IllegalStateException("Finish Speed Lab before MTU Retest.");
        operation.run();
    }
}
