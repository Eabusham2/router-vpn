package com.eabusham.routervpn;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Canonical Router VPN profile selection from a private Android node bundle.
 *
 * A bundle may omit selectedRouterID only for the initial single/default-node
 * case. Once it names a selected id, that exact profile must exist; falling
 * back to routerProfiles[0] would silently substitute another node's policy,
 * telemetry, forwarding, or runtime requirements.
 */
final class AndroidProfileSelection {
    static JSONObject selectedRouterProfile(JSONObject bundle) {
        if (bundle == null) throw new IllegalStateException("Router VPN bundle is missing.");
        JSONArray profiles = bundle.optJSONArray("routerProfiles");
        if (profiles == null) profiles = bundle.optJSONArray("router_profiles");
        if (profiles == null || profiles.length() == 0) {
            throw new IllegalStateException("Router VPN bundle has no Router profiles.");
        }

        String selected = bundle.optString(
                "selectedRouterID",
                bundle.optString("selected_id", "")
        ).trim();
        JSONObject first = null;
        for (int i = 0; i < profiles.length(); i++) {
            JSONObject profile = profiles.optJSONObject(i);
            if (profile == null) continue;
            if (first == null) first = profile;
            if (!selected.isEmpty() && selected.equals(profile.optString("id", "").trim())) {
                return profile;
            }
        }

        if (!selected.isEmpty()) {
            throw new IllegalStateException(
                    "Selected Router VPN profile '" + selected + "' is missing from this Android node bundle."
            );
        }
        if (first == null) throw new IllegalStateException("Router VPN bundle has no valid Router profile objects.");
        return first;
    }

    private AndroidProfileSelection() {}
}
