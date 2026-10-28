/* Owned native last-relay prerequisite. Public Compare admission is separate. */
#ifndef ROUTERVPN_LASTRELAY_H
#define ROUTERVPN_LASTRELAY_H
#include "core/or/or.h"
struct control_cmd_args_t;
struct relay_msg_t;
int routervpn_lastrelay_command(control_connection_t *,
                               const struct control_cmd_args_t *);
void routervpn_lastrelay_invalidate(void);
void routervpn_lastrelay_owner_closed(control_connection_t *);
void routervpn_lastrelay_free_all(void);
/* -2 means ordinary traffic; every recognized private address is consumed. */
int routervpn_lastrelay_attach(entry_connection_t *, origin_circuit_t *,
                              crypt_path_t *);
bool routervpn_lastrelay_reserved(const char *);
bool routervpn_lastrelay_current(entry_connection_t *);
void routervpn_lastrelay_connection_closed(entry_connection_t *);
int routervpn_lastrelay_send(edge_connection_t *, const char *, size_t);
int routervpn_lastrelay_receive(edge_connection_t *, const struct relay_msg_t *,
                               circuit_t *, crypt_path_t *);
void routervpn_lastrelay_fail(entry_connection_t *, const char *);
#endif
