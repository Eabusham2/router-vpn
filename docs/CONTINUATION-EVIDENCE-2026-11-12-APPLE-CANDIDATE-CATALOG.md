# Apple candidate catalog publication — 2026-11-12

This unit supplies the source-lifetime boundary for the retained-prefix candidate
feature. It does not yet enable the extension factory or Performance UI.

The app's private node store now invalidates its protected app-group publication
before each durable record commit. Successful commits publish the exact complete
record digest, including unsupported transports. A failed private write leaves
the old candidate generation invalid. A later successful publication cannot
revive it, including when original record bytes are restored. Publication failure
after a successful private write leaves candidate measurement unavailable while
preserving the successful private-store/RAM adoption result.

The publication carries a persistent epoch and monotonic generation. App startup
also advances it. Candidate capture checks the actual encrypted durable records
against RAM, then checks the live complete-record digest. Each private request
file is created exclusively with mode0600 beneath a mode0700 app-group directory.
PacketTunnel will read the same helper and compare original publication bytes,
request bytes, device/inode and nanosecond modification/change timestamps. An
identical-byte replacement therefore invalidates an admitted request. Cleanup
refuses to unlink a replacement source. The helper rejects symlinks, non-regular
files, foreign ownership, oversized inputs and unsafe request names.

`deploy/test_ios_candidate_catalog.py` executes the shipping publication helper
against real files and the shipping private commit method with only the private
store write and app-group location substituted. It covers old/new/reverted source,
unsupported-record changes, failed writes, replacement and stale cleanup,
symlinks and private permissions. Two causal variants fail as required: removing
request-file identity comparison, and moving publication invalidation after the
private durable write. Linux SHA256 uses the existing OpenSSL-backed CryptoKit
shim; this is not signed iOS/app-group or NetworkExtension acceptance.

The existing `test_ios_node_store_transactions.py` executable store/model suite
and `ios/RouterVPN/test_private_json_store_contract.py` also pass.

Extension factory lifecycle, exact receipt validation, and Performance display
remain separate follow-up units. No candidate TCP timing or live Apple acceptance
is claimed by this publication-only component.
