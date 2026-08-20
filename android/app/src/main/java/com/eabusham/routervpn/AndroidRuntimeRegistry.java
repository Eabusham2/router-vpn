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
