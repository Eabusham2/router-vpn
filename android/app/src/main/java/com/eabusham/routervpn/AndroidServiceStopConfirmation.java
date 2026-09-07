package com.eabusham.routervpn;

import java.util.HashMap;
import java.util.Map;
import java.util.function.LongConsumer;
import java.util.function.Supplier;

/** Process-owned confirmation of asynchronous embedded-service stop commands.
 *
 * A previously stored DOWN/FAILED/REVOKED value cannot acknowledge a new stop.
 * Only the matching service command may release its pending STOPPING state,
 * after shutdown and owned-session cleanup return. A failed dispatch or cleanup
 * remains pending, so callers retain ownership and may retry rather than leak.
 */
final class AndroidServiceStopConfirmation {
    static final String EXTRA_COMMAND = "routervpn_stop_command";
    private static final Map<String, Long> pending = new HashMap<>();
    private static long sequence;

    private AndroidServiceStopConfirmation() { throw new AssertionError(); }

    private static void requireChannel(String channel) {
        if (!"layered_state_v1".equals(channel) && !"xray_state_v1".equals(channel)) {
            throw new IllegalArgumentException("Unknown embedded VPN state channel.");
        }
    }

    static synchronized void request(String channel, LongConsumer dispatch) {
        requireChannel(channel);
        if (dispatch == null) throw new IllegalArgumentException("Stop dispatch is missing.");
        long command = Math.incrementExact(sequence);
        sequence = command;
        pending.put(channel, command);
        // Keep the pending command on dispatch failure: we cannot infer whether
        // Android accepted it before the caller received an exception.
        dispatch.accept(command);
    }

    static synchronized void start(String channel, Runnable dispatch) {
        requireChannel(channel);
        if (dispatch == null) throw new IllegalArgumentException("Start dispatch is missing.");
        if (pending.containsKey(channel)) {
            throw new IllegalStateException("Previous embedded VPN stop has not been acknowledged.");
        }
        // Serialize dispatch with stop requests; callers still own the normal
        // session/mutation guards and the subsequent selected-path proof.
        dispatch.run();
    }

    static synchronized String state(String channel, Supplier<String> reported) {
        requireChannel(channel);
        if (pending.containsKey(channel)) return "STOPPING";
        return reported.get();
    }

    static synchronized void acknowledge(String channel, long command) {
        requireChannel(channel);
        Long expected = pending.get(channel);
        if (command > 0 && expected != null && expected.longValue() == command) {
            pending.remove(channel);
        }
    }
}
