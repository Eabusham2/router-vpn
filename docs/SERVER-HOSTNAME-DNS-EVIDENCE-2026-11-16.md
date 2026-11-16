# Server hostname DNS transport evidence

The ARM64 and AMD64 Server runs at `3f1b4fc3` rejected an AAAA question at the encrypted hostname peer. The captured worker diagnostics retained the selected IPv4-only A lookup; the pinned TCP transport independently sends an A/ID1 and AAAA/ID2 pair while checking whether it can reuse its connection. Commit `268bcb27` distinguishes that transport pair from application-query evidence. The selected resolver, worker policy and encrypted traffic path remain unchanged.

This follow-on adds `TestRouterVPNServerHostnameActualTCPTransport`. It executes the actual pinned `dns/transport.NewTCPRaw` implementation against the existing hostname handler, with an explicitly modeled loopback listener and lower dial. It verifies the original ID0 A result, waits for the real reuse probes, and performs later application lookups whose wire IDs are assigned by the original multiplexer. The probe counters cannot satisfy the original application-query assertion. The test deliberately preserves the transport's reused-ID behavior rather than inventing a one-use restriction.

The encrypted Server gate runs this required root from its existing peer image before its original source and encrypted cases. It requires one exact successful terminal transcript. The original 46 encrypted cases, architecture requirements and existing per-case deadlines remain intact. This component observation does not replace those encrypted namespace cases or physical-device acceptance.

## Focused observations

The tested three-file source is based on `268bcb273dab771a069526985bee3613ffd33569` and composed unchanged onto `9dfc56c6c0c61b22f84e686400d3edfb5d8e50e7`.

| Check | Observed result |
|---|---|
| Actual pinned TCP transport, race instrumented | Compilation 5.344 seconds; test 0.030 seconds; passed |
| Compiled restoration of the old AAAA rejection | Failed on the intended captured-IPv4-question witness |
| Compiled counting of probes as application queries | Failed on the intended original-ID0-query witness |
| Encrypted-gate runner and verdict tests | 30 passed in 17.061 seconds |
| Existing hostname handler | Byte-identical to `268bcb27` |

The local TCP baseline image SHA-256 was `99f2721ed53886ff3a529b651eaec76dba53377ed49c245881a81b58a7c6693c`. Its terminal transcript SHA-256 was `ab8f400787e67a3ed013c70f910ecf7925040b717238c331e175abbfe42f7542`; the complete runner log SHA-256 was `1aa421a439d61eca11170ccedf75377c3e0a7bc5f28b5fddd84a3dd15142b10f`.

These are source and component-test observations. Exact-commit hosted native builds, encrypted Server acceptance, release publication, private deployment and physical-device acceptance require their own evidence.
