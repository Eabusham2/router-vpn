package com.eabusham.routervpn;

import android.content.SharedPreferences;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.function.BooleanSupplier;

/** One checked publication for CUSTOM choices plus the selected mode. */
final class AndroidCustomPresetCommit {
    static final String PRESETS = "custom_presets", MODE = "mode";
    static final int MAX_BYTES = 512 * 1024;

    static final class Snapshot {
        final SharedPreferences prefs;
        final String presets, mode;
        final boolean hadPresets, hadMode;
        Snapshot(SharedPreferences prefs) {
            this.prefs = Objects.requireNonNull(prefs);
            hadPresets = prefs.contains(PRESETS);
            hadMode = prefs.contains(MODE);
            presets = prefs.getString(PRESETS, "[]");
            mode = prefs.getString(MODE, "smart-auto");
            if (presets == null || mode == null || presets.getBytes(StandardCharsets.UTF_8).length > MAX_BYTES)
                throw new IllegalStateException("CUSTOM preference store is invalid or exceeds its size limit.");
        }
    }

    static boolean validName(String value) {
        if (value == null || value.isEmpty() || !value.equals(value.trim()) ||
                value.codePointCount(0, value.length()) > 64 || "new".equalsIgnoreCase(value)) return false;
        for (int i = 0; i < value.length();) {
            int cp = value.codePointAt(i);
            if (Character.isISOControl(cp) || cp == ':' || cp == '[' || cp == ']' ||
                    (cp >= Character.MIN_SURROGATE && cp <= Character.MAX_SURROGATE)) return false;
            i += Character.charCount(cp);
        }
        return true;
    }

    static java.util.List<String> editableLayers(java.util.List<String> catalog, java.util.List<String> saved) {
        java.util.LinkedHashSet<String> values = new java.util.LinkedHashSet<>(catalog);
        values.addAll(saved);
        return new java.util.ArrayList<>(values);
    }

    static Snapshot snapshot(SharedPreferences prefs) {
        synchronized (prefs) { return new Snapshot(prefs); }
    }

    private static void requireIdle(BooleanSupplier idle) {
        if (idle == null || !idle.getAsBoolean())
            throw new IllegalStateException("VPN state changed; disconnect/finish before saving CUSTOM presets.");
    }

    /** Callers validate every JSON row before this point. A failed commit may
     * still update Android's in-memory preferences, so restore both prior keys
     * and verify that restoration separately. No failure authorizes Connect. */
    static void publish(Snapshot before, String presets, String mode, BooleanSupplier idle) {
        if (before == null || presets == null || mode == null ||
                presets.getBytes(StandardCharsets.UTF_8).length > MAX_BYTES ||
                mode.isEmpty() || mode.length() > 256)
            throw new IllegalArgumentException("Invalid CUSTOM publication.");
        synchronized (before.prefs) {
            requireIdle(idle);
            SharedPreferences prefs = before.prefs;
            if (!Objects.equals(before.presets, prefs.getString(PRESETS, "[]")) ||
                    !Objects.equals(before.mode, prefs.getString(MODE, "smart-auto")) ||
                    before.hadPresets != prefs.contains(PRESETS) || before.hadMode != prefs.contains(MODE))
                throw new IllegalStateException("CUSTOM preferences changed; reopen the preset before saving.");
            RuntimeException failure;
            try {
                if (prefs.edit().putString(PRESETS, presets).putString(MODE, mode).commit()) return;
                failure = new IllegalStateException("Could not persist CUSTOM choices and selected mode.");
            } catch (RuntimeException error) { failure = error; }
            try {
                SharedPreferences.Editor restore = prefs.edit();
                if (before.hadPresets) restore.putString(PRESETS, before.presets); else restore.remove(PRESETS);
                if (before.hadMode) restore.putString(MODE, before.mode); else restore.remove(MODE);
                if (!restore.commit() || !Objects.equals(before.presets, prefs.getString(PRESETS, "[]")) ||
                        !Objects.equals(before.mode, prefs.getString(MODE, "smart-auto")) ||
                        before.hadPresets != prefs.contains(PRESETS) || before.hadMode != prefs.contains(MODE))
                    throw new IllegalStateException("CUSTOM rollback could not be confirmed.");
            } catch (RuntimeException rollback) {
                IllegalStateException combined = new IllegalStateException("CUSTOM save failed and rollback was incomplete; no connection was started.", failure);
                combined.addSuppressed(rollback);
                throw combined;
            }
            throw new IllegalStateException("CUSTOM save failed; prior choices were restored. No connection was started.", failure);
        }
    }
}
