# Native connected candidate ownership for SOCKS and CONNECT

## Behavior

The mobile bridge provides connected candidate measurement handles for the
complete original Local SOCKS5 and HTTP/HTTPS CONNECT chains. Each handle is
bound to the already-proved runtime, native engine, original source catalog
and selected packet prefix. A saved-prefix preparation cannot substitute for
that connected runtime.

Construction returns a unique reservation before calling the host catalog or
constructing the measurement service. The host stores that exact handle and
then calls its one-shot `Prepare`. Preparation keeps the original construction
deadline. Failure, expiry and cancellation close that handle; cleanup cannot
find and retire another operation by matching owner, position or inventory text.

Copied handles or owners, changed engines, stale slots, changed catalogs and
replacement runtimes are refused. `Close` joins admitted preparation, the
measurement service and outstanding catalog callbacks before clearing its own
slot. Native lifecycle cleanup checks original owner identity even if a copied
owner clears its candidate slot. Late cleanup cannot clear a replacement slot.

## Executed verification

The final 21 source files were frozen over `c89ec73290b8c94e3638d749244405733064dad9`.
Both full native test images compiled with race instrumentation and default Go
vet: the registered peer on the original desktop native core, and the complete
mobile Libbox client on its separately checked native core. All source inputs,
overlays and retained cores were checked again after execution.

The encrypted suite passed all nine required cases:

| Transport | Original chain sizes | Candidate measurements |
| --- | --- | --- |
| SOCKS5 | 3, 4, 8 | 50 successful TCP establishments per case |
| HTTP CONNECT | 3, 4, 8 | 50 successful TCP establishments per case |
| HTTPS CONNECT | 3, 4, 8 | 50 successful TCP establishments per case |

These are 450 measured candidate connections, with the original full-chain
proof, source ownership and cleanup still required. The partitioned Go output
contains 18 actual records: nine leaves and their repeated roots, or 11 distinct
test names. These counts are not additional independent network cases.

Periodic tunnel proofs also create connections. An earlier exact-delta check
incorrectly included that unrelated traffic, producing a delta of 65 alongside
50 candidate samples. The peer now separately counts a connection only after
the exact control target receives zero payload bytes, reaches remote EOF, and
its original socket closes successfully. Ten accounting records passed, and a
separately compiled omission of the zero-payload guard failed normally at the
required payload assertion. Proof traffic remains active throughout the test.

The final owner hardening passed 30 affected native component records and four
separately compiled copied-owner controls, including copied owners with cleared
slots. Earlier complete component execution on `47e4cd58` passed 36 records and
ten controls. Those earlier results are retained with their own source identity;
they are not represented as a new full run on `c89ec732`. The mandatory current
component gate requires all 38 records and 12 controls. The two focused Python
runner suites also passed all 18 checks on the final source.

The original bounds remain: 600 seconds per complete native compilation,
180 seconds for each encrypted Go case and 190 seconds for its joined process,
and 30/45 seconds for the accounting test/process. Negative controls require
their intended assertion and a normal failing exit. A timeout, build failure,
race, panic, skipped test or unrelated failure cannot satisfy a control.

The focused workflow and authoritative release require the native component and
encrypted gates. Preparation, required source inputs and aggregate artifact
validation include the new files. Existing ordinary and saved-prefix candidate
requirements remain in place.

| Evidence | Source / scope | SHA-256 |
| --- | --- | --- |
| Frozen 21-file source manifest | Final native source over `c89ec732` | `ce6dd9421bb6bdc0a3862b890bfffe0565be0dfbfbab18cee22f1d23ef2b6a58` |
| Affected ownership execution | 30 records and four compiled controls | `a018720cd54c58da1c29e870d0d18f43638a8b2abd00dcac0666766949f04958` |
| Encrypted and accounting execution | Nine cases, ten accounting records, one compiled control | `33870c4080e4163a82db0468f79edd913c5e62922426e3cbe3106b15c87bd473` |
| Earlier component execution | 36 records and ten controls on `47e4cd58` | `92a3506ef9ba6ac618e5e7470d94079cd44d91bfd5b33d5178481697de03c20f` |
| Final validation index | Separate source identities and joined worker result | `8fd1676948e8fa231d51a37660c110ac2057aa3a693780e2855d014c585d01e5` |

## Delivery boundaries

This change supplies the native bridge and required gates. Android and Apple
host adoption have separate session, source, binding and packaging checks.
Server/Compare execution-owner candidates and ordinary reservation cleanup
remain separate follow-ups.

Candidate TCP timing does not authenticate a replacement node or establish a
new working VPN configuration. Installed-device networking, leak/transition
tests, signing, private deployment and a green release of the final published
commit require their own evidence.
