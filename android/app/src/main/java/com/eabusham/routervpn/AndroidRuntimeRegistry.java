package com.eabusham.routervpn;

import android.content.Context;

/**
 * App-process owner for Android VPN engines.
 *
 * WireGuard/Amnezia GoBackend keep the running tunnel on the backend instance,
 * so Activities must not recreate those backends on rotation or window changes.
 * UI controllers are disposable; these engine objects live for the app process.
 */
final class AndroidRuntimeRegistry {
    private static AndroidRuntimeRegistry instance;

    final NativeWireGuardController wireGuard;
    final NativeAmneziaWGController amneziaWG;
    final NativeSingBoxController singBox;
    final NativeXrayController xray;
    final AndroidModeOrchestrator orchestrator;
    final AndroidMultihopRuntime multihop;

    private AndroidRuntimeRegistry(Context context) {
        Context app = context.getApplicationContext();
        wireGuard = new NativeWireGuardController(app);
        amneziaWG = new NativeAmneziaWGController(app);
        singBox = new NativeSingBoxController(app);
        xray = new NativeXrayController(app);
        orchestrator = new AndroidModeOrchestrator(app, wireGuard, amneziaWG, singBox, xray);
        multihop = new AndroidMultihopRuntime(app, singBox);
    }

    static synchronized AndroidRuntimeRegistry get(Context context) {
        if (instance == null) instance = new AndroidRuntimeRegistry(context);
        return instance;
    }

    private AndroidRuntimeRegistry() { throw new AssertionError(); }
}
