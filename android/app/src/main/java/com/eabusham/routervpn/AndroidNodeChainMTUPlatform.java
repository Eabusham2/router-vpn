package com.eabusham.routervpn;

import io.nekohasekai.libbox.CommandServer;
import io.nekohasekai.libbox.RouterMTUPlatform;
import io.nekohasekai.libbox.RouterMTUState;

/** Retains the original physical cleanup authority for each asynchronous native
 * MTU change. The native pause token still authorizes every cleanup socket. */
final class AndroidNodeChainMTUPlatform implements RouterMTUPlatform {
    private final AndroidNodeChainSession session;
    private final CommandServer server;
    private final AndroidNodeChainSession.Owner owner;
    private final RouterMTUPlatform platform;
    private AutoCloseable cleanup;

    AndroidNodeChainMTUPlatform(AndroidNodeChainSession session, CommandServer server,
                               AndroidNodeChainSession.Owner owner, RouterMTUPlatform platform) {
        if (session == null || server == null || owner == null || platform == null)
            throw new IllegalArgumentException("The ordered MTU platform needs its original owners.");
        this.session = session; this.server = server; this.owner = owner; this.platform = platform;
    }

    @Override public RouterMTUState captureMTU() { return platform.captureMTU(); }
    @Override public synchronized void beginMTUChange(RouterMTUState expected) throws Exception {
        if (cleanup != null) throw new IllegalStateException("The original MTU change has not joined.");
        platform.beginMTUChange(expected);
        try {
            // This callback must not reenter native proof/source validation:
            // the original native MTU owner holds its operation lock here.
            cleanup = owner.beginMTUCleanup(session, server, platform);
            if (cleanup == null) throw new IllegalStateException("The original MTU cleanup scope is unavailable.");
        } catch (Exception refused) {
            try { platform.endMTUChange(); } catch (Exception joined) { refused.addSuppressed(joined); }
            throw refused;
        }
    }
    @Override public synchronized void endMTUChange() throws Exception {
        AutoCloseable original = cleanup;
        if (original == null) throw new IllegalStateException("MTU completion has no original change owner.");
        try { platform.endMTUChange(); }
        finally {
            original.close();
            cleanup = null;
        }
    }
    @Override public void bindMTUSocket(RouterMTUState expected, long fd) throws Exception { platform.bindMTUSocket(expected, fd); }
    @Override public String readMTUCache() { return platform.readMTUCache(); }
    @Override public boolean compareAndSwapMTUCache(String expected, String replacement) { return platform.compareAndSwapMTUCache(expected, replacement); }
    @Override public void abortMTU(String reason) { platform.abortMTU(reason); }
}
