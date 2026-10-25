# Captured native-app startup policy

Requirement 116 in the recovered original requirement set includes persisted
startup and auto-connect settings. The reconciled native-app contract also
requires that a delayed operation cannot connect a different node after the
user changes the selection, private source, or connection policy.

## Desktop behavior

The controller captures the selected profile when scheduling its startup delay.
For an imported node it also captures the saved entry profile, execution
preference, and a digest of any private Router-entry runtime assets. A later
selection, relink, credential edit, policy edit, Disconnect, shutdown, or manual
Connect retires that intent. A failed manual Connect still takes priority over
the older automatic attempt.

Router nodes retain their existing AUTO, SMART AUTO, and Last-mode strategies.
Imported nodes connect with their own saved protocol and complete graph through
the same owned operation used by the Connect button. Startup does not replace
an imported protocol with a Router mode. New imported nodes retain their
existing Manual / auto-connect Off default.

| Imported-node choice | Behavior |
|---|---|
| Manual | Stay disconnected. Auto-connect cannot be enabled with Manual. |
| Saved connection | Start the saved protocol and entry/exit graph, then prove its selected DNS, policy, and required exit. |
| Last proven connection | Reuse a still-matching proved Local/Server choice when available, without rerunning Compare selection; create a new owned runtime and require fresh proof. |

An existing imported `smart-auto` startup value uses its saved protocol and
graph. The native imported-node editor displays this as Saved connection.
If Last has no matching evidence, startup tries the saved graph with fresh
proof. It never treats old evidence as proof that a new session is connected.

Last-state persistence contains node references, source/policy digests, the
protocol identifier, and the proved execution choice. It does not copy imported
credentials, keys, or private Router-entry assets into another store. Changing
the startup preference to Last does not itself invalidate the proved graph;
changing its credentials, requested policy, graph, or private assets does.

## Editing startup

Windows, macOS, and Linux expose imported-node startup from their native
Settings controls. The startup-only API is `/api/profile/startup`:

- GET returns the selected node ID, a revision token, its node kind, and its two
  startup preferences. It returns no protocol credentials or private bundle.
- POST requires the captured ID and revision, the selected startup choice, and
  an explicit auto-connect boolean. Unknown fields and additional JSON objects
  are rejected.
- Saving requires an idle owned controller transaction. The handler rechecks
  selection, source revision, connection state, and shutdown before persistence.
  A failed write restores the original in-memory profile.
- A successful edit changes only `startup_mode` and `auto_connect`, preserves
  all other node records and private policy, and retires the earlier delayed
  launch. It does not immediately connect the already-open application.

Router-specific settings remain on their existing API. The imported startup
editor never sends disabled Router-mode, Start Layer, MTU, or protection fields
back as default values.

## Shipping paths and verification

`cmd/client/strategy_modes.go` and `startup_external.go` own scheduling and Last
selection. `external_profile_connect.go` and `tor_bridge_routes.go` perform the
actual owned launch/proof; they are shared with interactive Connect. Private
source checks, cancellation, cleanup, and proof rejection remain in those paths.

`profile_startup_test.go` exercises API persistence and rollback across nine
imported protocol families, rejects stale selection/credentials/policy and
unknown inputs, and checks changes arriving during request decoding.
`startup_external_test.go` exercises captured startup using compiled native
graphs and isolated child processes, including failed proofs, cancellation,
changed entry assets, and retained Compare winners. These fixtures do not
establish off-LAN or physical-device network acceptance.

`deploy/test_desktop_startup_settings.py` compiles or executes the shipping
PowerShell, Swift, and GTK JSON serializers. The tests verify that only the
captured identity and chosen startup values are submitted, and reject mutated
identity/private-field behavior. The Windows workflow runs PowerShell 7 and
5.1; macOS and Linux run their native serializer checks and actual app builds.

## iOS and iPadOS

Auto-connect runs once per app model when Router VPN opens. It captures the
exact selected bundle, entry bundle and connection generation before reading
system VPN preferences. A newer selection, credentials/policy change,
Disconnect, or temporary Speed Lab owner retires that intent. Available VPNs
must remain idle through preference save/readback; startup never adopts an
already-active VPN or replaces a newer operation. Router startup rechecks the
same intent at nested Connect/SMART admissions and retains its own generation
across a valid Last fallback. SMART also revalidates startup after refreshing
VPN status before acquiring any native MTU measurement hold.

Imported nodes keep their own saved protocol and entry/exit graph. AUTO and
SMART reconnect that graph; Last retains the previous proved Local/Server
choice only when its source and entry still match. Durable Last state stores
hashes and the execution choice, without copying credentials or old runtime
receipts. Startup preferences and historical MTU readback do not invalidate
that history; requested MTU, credentials, DNS, protection and graph changes
do. A separate source-bound launch option requests the retained choice, and
the new native runtime must complete its normal fresh proofs. Speed Lab's
restore receipt and MTU lease remain separate.

The external Settings form saves only the two startup fields transactionally
while disconnected. New imported nodes remain Manual with auto-connect Off.
Live MTU/Retest/Cancel remains accessible for Router, ordinary external and
Tor paths. App startup does not promise device-boot/background execution or
add an on-demand rule by itself; existing strict protection retains its own
system on-demand behavior.

The shipping Swift fixtures exercise 274 startup and Settings checks, 672
multihop receipt checks, 64 app/provider strategy checks and 21 ownership
checks. Twelve startup mutations and the strategy suite's five existing
negative controls are rejected. These checks cover source behavior and
integration boundaries; exact-SHA Xcode builds and physical acceptance remain
separate requirements.
