# Router VPN Requirements Reconciliation

This document records the current requirement precedence used by the source and release gates.

1. Verified current source and exact-head evidence determine what is implemented.
2. Later explicit user corrections supersede contradictory older handoff text.
3. Requirements remain binding when they were never explicitly cancelled or replaced.
4. The final repository workflow is direct commits to `main`; old branch/PR instructions are cancelled.
5. The native Router VPN app is the map-first daily product. Setup Center remains private deployment, administration, download, recovery, and update infrastructure.
6. Source presence, shipping composition, native compilation, packaged artifacts, physical runtime, selected-path proof, and production deployment are separate evidence gates.

The reconciled scope includes the original 356 requirements, corrections C1–C7, later product/breakage additions, the unified map-first UI request, external node/hop/exit support where real, session and durable-state transaction corrections, exact-SHA release/update/recovery requirements, and ASUS fail-open household-network safety.

Setup Center package delivery is exact-SHA GitHub Release first, same-SHA Actions artifact second, then only a bounded local desktop/Portable fallback that the server can genuinely build. Android and iOS remain exact-SHA artifact-only. A generated package and its owned temporary build workspace are retained for retry for exactly 30 minutes from READY, without extending the deadline after download, then deleted. Explicit cancel/delete and shutdown clean them immediately.

Unsupported platform capabilities are disabled with a truthful reason; no UI may fake a working dataplane, route, DNS policy, exit proof, forwarding operation, multihop graph, or encryption layer.
