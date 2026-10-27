/* Router VPN's bounded outgoing circuit cover extension for pinned C Tor.
 * Distributed under the repository license; Tor integration retains Tor's
 * license. This interface is private to the daemon's main event loop. */
#ifndef ROUTERVPN_TOR_PADDING_H
#define ROUTERVPN_TOR_PADDING_H

#include "core/or/or.h"

struct control_cmd_args_t;

int routervpn_padding_command(control_connection_t *conn,
                              const struct control_cmd_args_t *args);
void routervpn_padding_invalidate(void);
void routervpn_padding_owner_closed(control_connection_t *conn);
void routervpn_padding_free_all(void);

/* Metadata follows the exact encrypted cell through Tor's existing queue.
 * None of these hooks alters a cell's payload, circuit, or wire format. */
void routervpn_padding_cell_created(circuit_t *circ, uint8_t command,
                                   const cell_t *cell);
void routervpn_padding_cell_queued(const cell_t *cell, packed_cell_t *copy,
                                  int wide_circ_ids);
void routervpn_padding_cell_written(packed_cell_t *cell, size_t bytes);
void routervpn_padding_cell_freed(packed_cell_t *cell);

#endif
