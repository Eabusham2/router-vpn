# Retained-prefix candidate TCP measurement core

The original August 19 custom-node/map request asks for candidate latency through
the selected prefix. Its source attribution and wider all-device scope remain in
[the November 12 ledger](CONTINUATION-EVIDENCE-2026-11-12.md). This unit supplies
the shared captured-source and measurement core; it does not establish native
host/UI adoption, encrypted candidate-path acceptance or complete delivery of
that requirement.

## Captured authority

`NodeChain.NewCandidatePlan` takes an original sealed chain, a prefix position
and the complete original candidate inventory with its host catalog revision.
Each candidate is parsed through the real paired NodeProfile or imported
external-policy compiler. Its literal TCP address and port come from that
validated source. Neither the measurement API nor Start accepts an arbitrary
destination, route tag, credential, replacement engine or WireGuard identity.

The current slice supports a retained paired WG/AWG Fast/AWG Strong prefix and
literal SS2022 candidates with Start Layer Off. All three verified SS2022
ciphers retain their original key lengths and source. UDP-only transports have
no guessed TCP port. A lazy SS prefix cannot claim a destination TCP connection
measurement from its upstream socket establishment; that broader prefix family
requires a different proved measurement capability.

The source hash binds the whole inventory, catalog revision, prefix position,
source/configuration identities and original proof. The host must implement a
fresh `CandidateInventoryCurrentContext` observation; a copied inventory alone
does not prove the current host catalog. Every operation also retains the five
native identity fields, original chain/controller pointer and original reader.
An observed integrity loss revokes this service even if the old value is later
restored. Host revisions must advance across change-away-and-back operations.

## Measurement and lifecycle

Each request chooses only a captured candidate ID and performs exactly fifty
new TCP connection establishments through the original prefix. A failed,
timed-out, stale or incomplete sample leaves that candidate without a score.
The receipt carries complete distribution statistics and the 10%-trimmed mean;
its label is `routed-tcp-connect`, not ICMP, HTTPS response time or candidate
credential/node proof. The source's private address and credentials are absent
from public status.

The existing 90-second request and five-second default drain bounds remain.
The original MTU hold survives cancellation, late dial completion and blocked
socket Close. Public results remain unavailable until actual worker/socket
drain. A successful receipt expires after 120 seconds; repeated reads do not
extend it. A native or catalog change invalidates the receipt before adoption.
No Local/Server comparison scoring formula or selected resolver is changed.

## Executed verification and remaining boundary

- Five hopmeasure test roots passed with Go 1.26.3 and the race detector in
  1.053 seconds. They perform fifty real loopback TCP connections, reject a
  failed subset score, retain late dial and blocked-close ownership, enforce
  receipt expiry and reject forged prefix/target inventories.
- Six shared NodeChain candidate roots passed with the race detector in
  5.477 seconds, including eighteen paired/imported/cipher/prefix combinations,
  exact source and endpoint preservation, all identity/reader/catalog losses,
  twelve invalid-source cases and original MTU ownership through cancellation.
- Those shared tests retain actual authenticated HTTP and public TLS proof
  fixtures while explicitly doubling the native route adapter. They do not
  certify encrypted WireGuard/AWG candidate traffic or a physical device.

Shipping mobile factories, desktop IPC, source-revision adoption, chooser
presentation/sorting and mandatory encrypted native witnesses remain separate
integration work. Other imported protocols, layers and prefix families remain
in the requirement ledger. A safe refusal is not counted as implementation of
those families, and this core is not a claim of a green complete release.
