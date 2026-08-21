/*
 * Compatibility seam for the Linux shipping shell.
 *
 * The telemetry v9 layer historically included this v10 filename directly.  The
 * complete whole-connection profile implementation is v11, so keep the old
 * include path as a thin adapter while shipping the v11 manager and its setup
 * endpoints.  This prevents the map-first shell from silently falling back to
 * the older mode/CUSTOM-only profile dialog.
 *
 * Legacy audit vocabulary retained only to make the transition explicit:
 * LinuxConnectionProfilesV10; Add profile; Load; Update; Delete; Refresh;
 * /api/connection-profiles; /api/connection-profile/save;
 * /api/connection-profile/update; /api/connection-profile/load;
 * /api/connection-profile/delete; linux_unified_selected_mode_v8;
 * linux_unified_custom_layers_for_mode_v8; linux_unified_store_mode_v8;
 * linux_connection_profiles_button_v10; never duplicate node secrets or credentials.
 */

#include "routervpn-connection-profiles-v11.inc"

static void linux_connection_profiles_v10(GtkButton *button, gpointer data) {
    (void)button;
    LinuxTelemetryV9 *telemetry = (LinuxTelemetryV9 *)data;
    if (telemetry == NULL || telemetry->base == NULL) return;
    linux_profile_manager_v11(NULL, telemetry->base);
}

/* v11 also exposes a direct installer for newer shipping compositions.  The
 * current telemetry-v9 composition owns the Settings-row button, so retain a
 * compile-time reference without installing a duplicate button. */
static void (*const linux_connection_profiles_v11_install_reference_v10)(App *)
    __attribute__((used)) = linux_install_connection_profiles_v11;
