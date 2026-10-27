/* Router VPN: bounded, outgoing-only cover on the captured Tor circuits.
 * All state and hooks run on Tor's main event loop. No new socket, circuit,
 * stream, relay protocol, or thread is introduced. See docs/TOR-PADDING.md. */

#include "core/or/or.h"
#include "core/mainloop/netstatus.h"
#include "core/or/channel.h"
#include "core/or/circuitlist.h"
#include "core/or/relay.h"
#include "core/or/cell_queue_st.h"
#include "core/or/cpath_build_state_st.h"
#include "core/or/crypt_path_st.h"
#include "core/or/origin_circuit_st.h"
#include "feature/control/control_cmd_args_st.h"
#include "feature/control/control.h"
#include "feature/control/control_connection_st.h"
#include "feature/control/control_proto.h"
#include "feature/control/routervpn_padding.h"
#include "lib/crypt_ops/crypto_rand.h"
#include "lib/crypt_ops/crypto_util.h"
#include "lib/evloop/timers.h"
#include "lib/time/compat_time.h"

#define RVPN_MIN_RATE 32
#define RVPN_MAX_RATE 192
#define RVPN_MIN_TTL_MS 100
#define RVPN_MAX_TTL_MS 10000

/* A single budget covers every eligible circuit in this daemon. At most one
 * of our cells may wait in a circuit queue. Existing Tor padding is separate
 * and is neither disabled nor counted as Router VPN cover. */
static struct {
  control_connection_t *owner;
  tor_timer_t *timer;
  bool active;
  const char *reason;
  char session[65];
  char source[65];
  char username[65];
  char password[65];
  uint64_t generation;
  uint64_t expires_usec;
  uint64_t next_usec;
  uint64_t queued_cells;
  uint64_t queued_bytes;
  uint64_t channel_cells;
  uint64_t channel_bytes;
  uint64_t dropped_cells;
  uint64_t dropped_bytes;
  uint64_t pending_bytes;
  uint32_t last_circuit;
  unsigned username_len;
  unsigned rate;
  /* Only the stack cell created by our synchronous DROP call can be tagged.
   * In particular, a padding-machine callback nested inside that call cannot
   * borrow its receipt. Neither pointer survives that call. */
  circuit_t *creating_circuit;
  const cell_t *created_cell;
} cover;

static uint64_t generation_highwater;

static bool
hex_length(const char *value, size_t length)
{
  if (!value || strlen(value) != length)
    return false;
  for (size_t i = 0; i < length; ++i) {
    if (!(value[i] >= '0' && value[i] <= '9') &&
        !(value[i] >= 'a' && value[i] <= 'f'))
      return false;
  }
  return true;
}

static bool
hex64(const char *value)
{
  return hex_length(value, 64);
}

static bool
hex_username(const char *value)
{
  /* Desktop's existing captured session is 16 random bytes; the mobile and
   * server native owners use 32. Both are encoded as canonical lower hex. */
  return hex_length(value, 32) || hex_length(value, 64);
}

/* The control protocol accepts canonical decimal integers only. */
static bool
decimal(const char *value, uint64_t min, uint64_t max, uint64_t *out)
{
  uint64_t result = 0;
  if (!value || !value[0] || (value[0] == '0' && value[1]))
    return false;
  for (const char *p = value; *p; ++p) {
    if (*p < '0' || *p > '9' || result > (max - (*p - '0')) / 10)
      return false;
    result = result * 10 + (*p - '0');
  }
  if (result < min || result > max)
    return false;
  *out = result;
  return true;
}

static bool
owner_open(control_connection_t *owner)
{
  return owner && owner->is_owning_control_connection &&
         owner->base_.state == CONTROL_CONN_STATE_OPEN &&
         !owner->base_.marked_for_close;
}

static void
stop_cover(const char *reason)
{
  cover.active = false;
  cover.reason = reason;
  cover.expires_usec = 0;
  cover.next_usec = 0;
  cover.creating_circuit = NULL;
  cover.created_cell = NULL;
  if (cover.timer)
    timer_disable(cover.timer);
  memwipe(cover.username, 0, sizeof(cover.username));
  cover.username_len = 0;
  memwipe(cover.password, 0, sizeof(cover.password));
  /* Already encrypted cells must not be removed from an open circuit: doing
   * that would desynchronize its cipher. STOP reports stopping until our
   * one queued cell is handed to the channel or discarded by Tor teardown. */
}

static void
check_lifetime(uint64_t now)
{
  if (!cover.active)
    return;
  if (!owner_open(cover.owner))
    stop_cover("owner");
  else if (net_is_disabled() || !is_participating_on_network())
    stop_cover("disabled");
  else if (now >= cover.expires_usec)
    stop_cover("expired");
}

void
routervpn_padding_invalidate(void)
{
  if (cover.active)
    stop_cover("configuration");
}

void
routervpn_padding_owner_closed(control_connection_t *conn)
{
  if (cover.owner == conn) {
    stop_cover("owner");
    cover.owner = NULL;
  }
}

void
routervpn_padding_free_all(void)
{
  stop_cover("shutdown");
  timer_free(cover.timer);
  memwipe(&cover, 0, sizeof(cover));
  generation_highwater = 0;
}

static bool
eligible(origin_circuit_t *origin)
{
  circuit_t *circ = TO_CIRCUIT(origin);
  if (circ->marked_for_close || circ->state != CIRCUIT_STATE_OPEN ||
      circ->purpose != CIRCUIT_PURPOSE_C_GENERAL || !circ->n_chan ||
      !CHANNEL_IS_OPEN(circ->n_chan) || circ->circuit_blocked_on_n_chan ||
      circ->n_chan_cells.n || channel_num_cells_writeable(circ->n_chan) < 1 ||
      !origin->build_state || origin->build_state->onehop_tunnel ||
      origin->build_state->is_internal || !origin->isolation_values_set ||
      !origin->isolation_any_streams_attached ||
      (origin->isolation_flags_mixed & ISO_SOCKSAUTH) ||
      origin->socks_username_len != cover.username_len ||
      origin->socks_password_len != 64 ||
      !origin->socks_username || !origin->socks_password ||
      !tor_memeq(origin->socks_username, cover.username, cover.username_len) ||
      !tor_memeq(origin->socks_password, cover.password, 64) ||
      (origin->unusable_for_new_conns && !origin->p_streams) ||
      !origin->cpath || circuit_get_cpath_len(origin) < 3)
    return false;
  crypt_path_t *hop = origin->cpath;
  do {
    if (hop->state != CPATH_STATE_OPEN)
      return false;
    hop = hop->next;
  } while (hop != origin->cpath);
  return true;
}

/* Fair selection does not build, extend, keep alive, or change a circuit. */
static origin_circuit_t *
select_circuit(void)
{
  origin_circuit_t *after = NULL, *first = NULL;
  SMARTLIST_FOREACH_BEGIN(circuit_get_global_origin_circuit_list(),
                         origin_circuit_t *, origin) {
    if (!eligible(origin))
      continue;
    uint32_t id = origin->global_identifier;
    if (!first || id < first->global_identifier)
      first = origin;
    if (id > cover.last_circuit &&
        (!after || id < after->global_identifier))
      after = origin;
  } SMARTLIST_FOREACH_END(origin);
  return after ? after : first;
}

static uint64_t
next_interval(void)
{
  /* Ceiling the interval for a 514-byte link cell can never exceed the
   * configured rate, including on 512-byte links. Jitter only adds delay:
   * instantaneous scheduling is 75--100% of the ceiling. There is no token
   * accumulation or catch-up burst after a delayed event-loop callback. */
  uint64_t min = (UINT64_C(514) * 8000 + cover.rate - 1) / cover.rate;
  return min + crypto_rand_uint64(min / 3 + 1);
}

static void
schedule_cover(uint64_t now)
{
  if (!cover.active)
    return;
  uint64_t due = MIN(cover.next_usec, cover.expires_usec);
  uint64_t delay = due > now ? due - now : 1;
  /* Pinned Tor's timer wheel truncates delays to 100-us ticks. Round up so
   * an early callback cannot requeue itself at zero ticks and busy-spin. */
  delay = ((delay + 99) / 100) * 100;
  struct timeval timeout = { (long)(delay / 1000000),
                            (long)(delay % 1000000) };
  timer_schedule(cover.timer, &timeout);
}

static void
cover_callback(tor_timer_t *timer, void *arg,
               const struct monotime_t *when)
{
  (void)timer; (void)arg; (void)when;
  uint64_t now = monotime_absolute_usec();
  check_lifetime(now);
  if (!cover.active)
    return;
  if (now < cover.next_usec) {
    schedule_cover(now);
    return;
  }
  if (!cover.pending_bytes) {
    origin_circuit_t *origin = select_circuit();
    if (origin) {
      uint64_t previous = cover.queued_cells;
      cover.last_circuit = origin->global_identifier;
      cover.creating_circuit = TO_CIRCUIT(origin);
      /* DROP is not a Conflux-multiplexed command. The ordinary Tor relay
       * path encodes and encrypts it through every hop to this circuit's
       * exit, then its scheduler owns the resulting packed cell. */
      int result = relay_send_command_from_edge(0, TO_CIRCUIT(origin),
          RELAY_COMMAND_DROP, NULL, 0, origin->cpath->prev);
      cover.creating_circuit = NULL;
      cover.created_cell = NULL;
      if (result < 0 || cover.queued_cells != previous + 1) {
        stop_cover("send-error");
        return;
      }
    }
  }
  cover.next_usec = now + next_interval();
  schedule_cover(now);
}

void
routervpn_padding_cell_created(circuit_t *circ, uint8_t command,
                              const cell_t *cell)
{
  if (cover.active && cover.creating_circuit == circ &&
      command == RELAY_COMMAND_DROP) {
    cover.creating_circuit = NULL;
    cover.created_cell = cell;
  }
}

void
routervpn_padding_cell_queued(const cell_t *cell, packed_cell_t *copy,
                             int wide_circ_ids)
{
  if (!cover.active || !cover.created_cell || cell != cover.created_cell)
    return;
  cover.created_cell = NULL;
  tor_assert(!cover.pending_bytes);
  copy->routervpn_padding_generation = cover.generation;
  cover.pending_bytes = get_cell_network_size(wide_circ_ids);
  ++cover.queued_cells;
  cover.queued_bytes += cover.pending_bytes;
}

void
routervpn_padding_cell_written(packed_cell_t *cell, size_t bytes)
{
  if (!cell->routervpn_padding_generation)
    return;
  tor_assert(cell->routervpn_padding_generation == cover.generation);
  tor_assert(bytes == cover.pending_bytes);
  ++cover.channel_cells;
  cover.channel_bytes += bytes;
  cover.pending_bytes = 0;
  cell->routervpn_padding_generation = 0;
}

void
routervpn_padding_cell_freed(packed_cell_t *cell)
{
  if (!cell->routervpn_padding_generation)
    return;
  tor_assert(cell->routervpn_padding_generation == cover.generation);
  tor_assert(cover.pending_bytes);
  ++cover.dropped_cells;
  cover.dropped_bytes += cover.pending_bytes;
  cover.pending_bytes = 0;
  cell->routervpn_padding_generation = 0;
}

static void
reply_status(control_connection_t *conn)
{
  uint64_t now = monotime_absolute_usec();
  check_lifetime(now);
  control_printf_endreply(conn, 250,
      "version=1 state=%s reason=%s session=%s source=%s generation=%"PRIu64
      " rate_kbps=%u expires_ms=%"PRIu64" queued_cells=%"PRIu64
      " queued_cell_bytes=%"PRIu64" channel_cells=%"PRIu64
      " channel_cell_bytes=%"PRIu64" dropped_cells=%"PRIu64
      " dropped_cell_bytes=%"PRIu64" pending_cells=%u last_circuit=%u",
      cover.active ? "running" : cover.pending_bytes ? "stopping" : "stopped",
      cover.active ? "active" : cover.reason ? cover.reason : "idle",
      cover.session, cover.source, cover.generation, cover.rate,
      cover.active ? (cover.expires_usec - now + 999) / 1000 : 0,
      cover.queued_cells, cover.queued_bytes, cover.channel_cells,
      cover.channel_bytes, cover.dropped_cells, cover.dropped_bytes,
      cover.pending_bytes ? 1 : 0, cover.last_circuit);
}

int
routervpn_padding_command(control_connection_t *conn,
                          const struct control_cmd_args_t *args)
{
  int count = smartlist_len(args->args);
  const char *action = count ? smartlist_get(args->args, 0) : "";
  uint64_t now = monotime_absolute_usec();
  uint64_t generation, rate, ttl;
  check_lifetime(now);
  if (!owner_open(conn)) {
    control_printf_endreply(conn, 551, "Padding requires the owning controller");
    return 0;
  }
  if (!strcmp(action, "INFO") && count == 1) {
    control_printf_endreply(conn, 250,
        "version=1 direction=outgoing min_rate_kbps=32 max_rate_kbps=192"
        " default_rate_kbps=192 max_ttl_ms=10000 max_pending_cells=1"
        " accounting=tor-link-cell username_hex_lengths=32,64"
        " password_hex_length=64 generation_highwater=%"PRIu64,
        generation_highwater);
    return 0;
  }
  if (count < 4 || !hex64(smartlist_get(args->args, 1)) ||
      !hex64(smartlist_get(args->args, 2)) ||
      !decimal(smartlist_get(args->args, 3), 1, INT64_MAX, &generation))
    goto invalid;
  const char *session = smartlist_get(args->args, 1);
  const char *source = smartlist_get(args->args, 2);
  if (!strcmp(action, "START") && count == 8) {
    if (!decimal(smartlist_get(args->args, 4), RVPN_MIN_RATE,
                 RVPN_MAX_RATE, &rate) ||
        !decimal(smartlist_get(args->args, 5), RVPN_MIN_TTL_MS,
                 RVPN_MAX_TTL_MS, &ttl) ||
        !hex_username(smartlist_get(args->args, 6)) ||
        !hex64(smartlist_get(args->args, 7)))
      goto invalid;
    if (cover.active || cover.pending_bytes ||
        (cover.owner && cover.owner != conn) ||
        generation <= generation_highwater || net_is_disabled() ||
        !is_participating_on_network()) {
      control_printf_endreply(conn, 551, "Padding start is stale or unavailable");
      return 0;
    }
    tor_timer_t *timer = cover.timer;
    memwipe(&cover, 0, sizeof(cover));
    cover.timer = timer ? timer : timer_new(cover_callback, NULL);
    cover.owner = conn;
    cover.active = true;
    cover.generation = generation_highwater = generation;
    cover.rate = (unsigned)rate;
    memcpy(cover.session, session, 65);
    memcpy(cover.source, source, 65);
    cover.username_len = (unsigned)strlen(smartlist_get(args->args, 6));
    memcpy(cover.username, smartlist_get(args->args, 6), cover.username_len + 1);
    memcpy(cover.password, smartlist_get(args->args, 7), 65);
    cover.expires_usec = now + ttl * 1000;
    cover.next_usec = now + next_interval();
    schedule_cover(now);
    reply_status(conn);
    return 0;
  }
  if (cover.owner != conn || cover.generation != generation ||
      !tor_memeq(cover.session, session, 64) ||
      !tor_memeq(cover.source, source, 64)) {
    control_printf_endreply(conn, 551, "Padding owner is stale");
    return 0;
  }
  if (!strcmp(action, "RENEW") && count == 5) {
    if (!decimal(smartlist_get(args->args, 4), RVPN_MIN_TTL_MS,
                 RVPN_MAX_TTL_MS, &ttl))
      goto invalid;
    if (!cover.active) {
      control_printf_endreply(conn, 551, "Padding proof has expired or stopped");
      return 0;
    }
    cover.expires_usec = now + ttl * 1000;
    schedule_cover(now);
  } else if (!strcmp(action, "STOP") && count == 4) {
    if (cover.active)
      stop_cover("controller");
  } else if (strcmp(action, "STATUS") || count != 4) {
    goto invalid;
  }
  reply_status(conn);
  return 0;

 invalid:
  control_printf_endreply(conn, 512, "Invalid bounded padding command");
  return 0;
}
