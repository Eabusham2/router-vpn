package com.eabusham.routervpn;

import android.content.Context;
import java.io.File;

/** Captures one native entry and external exit under the existing VPN owner. */
final class AndroidStandardExitController {
    private final Context context;

    AndroidStandardExitController(Context context) { this.context=context.getApplicationContext(); }

    NativeSingBoxController.SessionInfo prepare(File entryBundle, AndroidStandardExitStore.Entry exit) throws Exception {
        return prepare(entryBundle,exit,"wg");
    }

    NativeSingBoxController.SessionInfo prepare(File entryBundle, AndroidStandardExitStore.Entry exit, String entryMode) throws Exception {
        AndroidStandardExitStore.validate(exit);
        if(entryBundle==null)throw new IllegalArgumentException("Choose the captured Router VPN entry.");
        if(AndroidTorProfile.isTor(exit.protocol))return AndroidTorProfile.prepare(context, entryBundle, exit, entryMode);
        if(AndroidExternalPolicy.supports(exit.protocol))return AndroidExternalPolicy.prepare(context, entryBundle, exit, entryMode);
        throw new IllegalArgumentException("The selected external protocol has no captured native policy owner.");
    }
    NativeSingBoxController.SessionInfo prepare(File entryBundle, AndroidStandardExitStore.Entry exit, String entryMode, String execution, String restoredExecution) throws Exception {
        AndroidStandardExitStore.validate(exit);
        AndroidStandardExitStore.validateExecution(exit,entryBundle!=null,execution);
        if(AndroidTorProfile.isTor(exit.protocol)){
            if(!restoredExecution.isEmpty()&&!execution.equals(restoredExecution))throw new IllegalArgumentException("The proved Tor execution differs from its captured restoration choice.");
            return AndroidTorProfile.prepare(context,entryBundle,exit,entryMode,execution);
        }
        if("local".equals(execution)&&restoredExecution.isEmpty())return prepare(entryBundle,exit,entryMode);
        return AndroidExternalPolicy.prepare(context,entryBundle,exit,entryMode,execution,restoredExecution);
    }

}
