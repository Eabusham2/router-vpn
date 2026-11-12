# Apple candidate capture and receipt validation — 2026-11-12

This follows the durable catalog publication component. It adds app-side original
source capture and strict metadata/receipt parsing. Extension and UI adoption are
not enabled by this component alone.

Capture enumerates every durable saved record, binds the full publication digest,
and retains unsupported rows without scores. Eligible rows use the shipping
paired/imported original-source compiler and its pure candidate validator. The
inventory excludes original prefix identities and uses the publication revision;
no caller-selected address, proxy port or synthetic proof is introduced. Only
original WG/AWG packet prefixes are accepted for TCP connection timing.

Receipt validation binds the original request, capture, prefix identity/position,
candidate identity/source and exact 120000ms lifetime. It requires one ready
candidate row, fifty completed TCP attempts, zero failures, complete/drained state,
finite ordered statistics and a trimmed mean inside the measured distribution.
An expired receipt cannot be renewed by reading it again.

`deploy/test_ios_node_candidates.py` passed **46 shipping Swift/shared Go capture
and receipt checks**: original paired and imported sources for all three SS2022
ciphers, unsupported source rows, lazy-prefix refusal, foreign/incomplete/expired
receipts and failed sample counts. It compiles actual Go original-source APIs;
the process bridge supplies only the gomobile boundary. Two causal variants are
rejected: bypassing shared candidate-source eligibility, and accepting a changed
expiry interval. No sockets, native session readiness or signed Apple application
execution are claimed by this source/receipt test.
