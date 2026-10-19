#ifndef ROUTERVPN_TOR_HOST_H
#define ROUTERVPN_TOR_HOST_H
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ROUTERVPN_TOR_ABI 1

/* Exactly one Tor C invocation per process. Arguments are copied before the
 * thread starts. Only generated, validated arguments may cross this interface.
 * start returns -2 while an instance is owned and -3 after its final shutdown.
 * VPN sessions reconfigure the resident instance through its owning control
 * socket; they MUST NOT call close and attempt another Tor invocation. */
int32_t routervpn_tor_abi(void);
const char *routervpn_tor_version(void);
int32_t routervpn_tor_start(const char *const *arguments, size_t count,
                           uint64_t *handle);

/* Claims the caller-owned descriptor for Tor's preauthenticated owning control
 * socket exactly once. It is a socketpair, never a TCP control listener. */
int32_t routervpn_tor_control(uint64_t handle);

/* 0 = running, 1 = exited, -1 = unknown handle. Does not release ownership. */
int32_t routervpn_tor_status(uint64_t handle, int32_t *exit_code);

/* Final process-lifetime shutdown, not VPN-session disconnect. Shuts down the
 * owning socket and waits at most wait_ms (0..5000). Returns
 * 0 only after the native thread is joined and host storage is released.
 * 1 means still stopping: the handle remains owned and close MUST be retried.
 * A successful start can never follow this operation in the same process.
 * Never sends a process signal or cancels a thread inside Tor. */
int32_t routervpn_tor_close(uint64_t handle, uint32_t wait_ms);

#ifdef __cplusplus
}
#endif
#endif
