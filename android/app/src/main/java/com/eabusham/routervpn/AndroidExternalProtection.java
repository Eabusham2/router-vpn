package com.eabusham.routervpn;

import org.json.JSONObject;

import java.util.Arrays;
import java.util.Locale;

/** Saved exit protection and its independently captured predecessor requirement. */
final class AndroidExternalProtection {
    static void validate(JSONObject policy) throws Exception {
        if (policy == null) throw new IllegalArgumentException("External protection has no saved policy owner.");
        if (policy.has("kill_switch") && !(policy.get("kill_switch") instanceof Boolean)) {
            throw new IllegalArgumentException("Kill switch must be explicitly On or Off.");
        }
        if (policy.has("kill_switch_policy")) {
            Object value = policy.get("kill_switch_policy");
            if (!(value instanceof String) || !Arrays.asList("off", "on-connect", "always", "strict", "lockdown", "on", "enabled").contains(normalize((String) value))) {
                throw new IllegalArgumentException("Choose a supported saved kill-switch policy.");
            }
        }
    }

    static boolean requested(JSONObject policy, boolean legacyDefault) throws Exception {
        validate(policy);
        if (!policy.has("kill_switch") && !policy.has("kill_switch_policy")) return legacyDefault;
        return policy.optBoolean("kill_switch", false)
                || policy.has("kill_switch_policy") && !"off".equals(normalize(policy.getString("kill_switch_policy")));
    }

    /** Only the two protection fields change; DNS, keys and graph remain captured. */
    static JSONObject withChoice(JSONObject policy, boolean enabled) throws Exception {
        validate(policy);
        return new JSONObject(policy.toString()).put("kill_switch", enabled)
                .put("kill_switch_policy", enabled ? "always" : "off");
    }

    static boolean entryRequested(JSONObject entry) throws Exception {
        if (entry == null) return false;
        // Preserve the predecessor's established strict policy independently.
        if (entry.has("kill_switch") && !(entry.get("kill_switch") instanceof Boolean)) {
            throw new IllegalArgumentException("The captured entry has an invalid kill switch.");
        }
        if (entry.has("kill_switch_policy") && !(entry.get("kill_switch_policy") instanceof String)) {
            throw new IllegalArgumentException("The captured entry has an invalid protection policy.");
        }
        String policy = normalize(entry.optString("kill_switch_policy", "off"));
        return entry.optBoolean("kill_switch", false) || Arrays.asList("always", "strict", "lockdown").contains(policy);
    }

    static boolean externalCapture(JSONObject capture) throws Exception {
        JSONObject profile = capture.getJSONObject("profile");
        if (!capture.getString("exit_id").equals(profile.getString("id"))) {
            throw new IllegalArgumentException("Protection lost the captured external node.");
        }
        JSONObject entry = capture.has("entry") ? capture.getJSONObject("entry") : null;
        // Older direct saves required lockdown; older via-entry saves retained
        // the independent entry policy. Only an explicit saved choice changes it.
        boolean selected = requested(profile, entry == null), predecessor = entryRequested(entry);
        return selected || predecessor;
    }

    static boolean torCapture(JSONObject metadata) throws Exception {
        JSONObject profile = metadata.getJSONObject("tor_profile");
        if (!metadata.getString("external_id").equals(profile.getString("id"))) {
            throw new IllegalArgumentException("Protection lost the captured Tor node.");
        }
        JSONObject entry = metadata.has("predecessor_profile") ? metadata.getJSONObject("predecessor_profile") : null;
        boolean selected = requested(profile, true), predecessor = entryRequested(entry);
        return selected || predecessor;
    }

    /** Runs after the native graph and capture have been independently checked. */
    static void requireSession(boolean marker, boolean required, int sdk, boolean alwaysOn, boolean lockdown) {
        if (marker != required) throw new IllegalStateException("The captured external protection and its private session marker disagree.");
        if (required && (sdk < 29 || !alwaysOn || !lockdown)) {
            throw new IllegalStateException("This captured external path requires Android 10 or newer, Always-on VPN and Block connections without VPN.");
        }
    }

    private static String normalize(String value) { return value.trim().toLowerCase(Locale.US); }
    private AndroidExternalProtection() {}
}
