# Exact-SHA release evidence

Router VPN treats source, shipped artifacts, native compilation, runtime proof, and production deployment as separate evidence classes.

A repository generation is GitHub-complete only when one exact current source SHA has green evidence for:

- source, security, recovered requirements, and durable-state transactions;
- an exact-source snapshot;
- Windows installed and Portable packages for x64 and ARM64;
- macOS packages for Intel and Apple Silicon;
- Linux packages for x64 and ARM64;
- Android APK and real iOS/iPadOS native build output;
- ARM64 server images and Portainer preflight;
- aggregate package/provenance checks; and
- a production compose materialized entirely from that same SHA.

Reusable release workflows include the caller run ID in their concurrency ownership key. A standalone diagnostic dispatch therefore cannot cancel jobs owned by the authoritative Build-all run for the same source SHA.

Old green artifacts or statuses never certify a newer source generation. Production remains on the last deliberately verified generation until the complete exact-current chain is green.
