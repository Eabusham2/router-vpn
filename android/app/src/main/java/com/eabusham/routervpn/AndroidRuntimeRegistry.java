package com.eabusham.routervpn;

import android.content.Context;

/** App-process owner for Android VPN engines and session revalidation. */
final class AndroidRuntimeRegistry {
    private static AndroidRuntimeRegistry instance;

    final NativeWireGuardController wireGuard;
    final NativeAmneziaWGController amneziaWG;
    final NativeSingBoxController singBox;
    final NativeXrayController xray;
    final AndroidModeOrchestrator orchestrator;
    final AndroidMultihopRuntime multihop;
    final AndroidStandardExitRuntime standardExit;
    final AndroidSessionRevalidator revalidator;

    private AndroidRuntimeRegistry(Context context) {
        Context app = context.getApplicationContext();
        // Every tunnel engine below is owned by this Android app process and the
        // VpnService implementations are START_NOT_STICKY. Invalidate previous-
        // process Connected/UP evidence before any controller can restore it.
        AndroidProcessStateReconciler.reconcile(app);
        wireGuard = new NativeWireGuardController(app);
        amneziaWG = new NativeAmneziaWGController(app);
        singBox = new NativeSingBoxController(app);
        xray = new NativeXrayController(app);
        orchestrator = new AndroidModeOrchestrator(app, wireGuard, amneziaWG, singBox, xray);
        multihop = new AndroidMultihopRuntime(app, singBox);
        standardExit = new AndroidStandardExitRuntime(app, singBox);
        revalidator = new AndroidSessionRevalidator(app, this);
        revalidator.start();
    }

    static synchronized AndroidRuntimeRegistry get(Context context) {
        if (instance == null) instance = new AndroidRuntimeRegistry(context);
        return instance;
    }

    private AndroidRuntimeRegistry() { throw new AssertionError(); }
}
