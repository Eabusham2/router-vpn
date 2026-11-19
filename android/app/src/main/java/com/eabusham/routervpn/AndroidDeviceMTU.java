package com.eabusham.routervpn;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.UUID;

/** One opt-in client-interface request, independent of saved node policies. */
final class AndroidDeviceMTU {
    static final String KEY = "device_mtu_request";
    final String source;
    final String revision;
    final int value;

    private AndroidDeviceMTU(String source) {
        this.source = source;
        if (source.isEmpty()) {
            revision = "";
            value = 0;
            return;
        }
        if (!source.matches("[0-9a-f]{32}/(off|[1-9][0-9]{3})"))
            throw new IllegalStateException("The saved device MTU request is invalid.");
        revision = source.substring(0, 32);
        String setting = source.substring(33);
        value = "off".equals(setting) ? 0 : Integer.parseInt(setting);
        if (value != 0) requireRange(value);
    }

    private static SharedPreferences preferences(Context context) {
        return context.getApplicationContext().getSharedPreferences("router-vpn-unified", Context.MODE_PRIVATE);
    }

    static AndroidDeviceMTU capture(Context context) {
        return new AndroidDeviceMTU(preferences(context).getString(KEY, ""));
    }

    static void requireRange(int value) {
        if (value < 1280 || value > 9000)
            throw new IllegalArgumentException("Choose a device MTU between 1280 and 9000.");
    }

    void requireCurrent(Context context) {
        if (!source.equals(preferences(context).getString(KEY, "")))
            throw new IllegalStateException("The device MTU request changed. Start the connection again.");
    }

    static AndroidDeviceMTU fromLaunch(Context context, String original) {
        AndroidDeviceMTU captured = new AndroidDeviceMTU(original == null ? "" : original);
        captured.requireCurrent(context);
        return captured;
    }

    static synchronized void save(Context context, AndroidDeviceMTU original, int value) {
        if (value != 0) requireRange(value);
        original.requireCurrent(context);
        String revision = UUID.randomUUID().toString().replace("-", "");
        if (!preferences(context).edit().putString(KEY, revision + "/" + (value == 0 ? "off" : value)).commit())
            throw new IllegalStateException("Android could not save the device MTU request.");
    }

    int interfaceValue(int configured, boolean jumbo) {
        if (value == 0) return configured;
        if (jumbo && value != 9000)
            throw new IllegalArgumentException("This profile requires Jumbo 9000. Choose 9000 or turn off the device MTU.");
        return value;
    }
}
