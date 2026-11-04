# Physical/live exact-SHA release evidence

GitHub completion and whole-project release are separate. After one exact `main` SHA passes the authoritative native/package/image/compose chain, use `deploy/live-release-evidence.py` for the remaining physical/live gates. The tool never turns source or CI success into a live PASS.

Initialize a manifest for the exact already-green release SHA:

```bash
python3 deploy/live-release-evidence.py init release-evidence.json --sha <40-char-main-sha>
```

After executing a real gate, keep the raw evidence outside the public repository and record its digest:

```bash
python3 deploy/live-release-evidence.py record release-evidence.json \
  --gate physical-android --status pass \
  --evidence /private/evidence/android-network-transition.txt \
  --note "real-device validation"
```

PASS is refused without at least one evidence file. The manifest stores each evidence file's SHA-256, size, resolved source path and UTC capture time. Final validation re-hashes those raw files, so missing or modified proof loses credit. It does not copy evidence into the repository, so do not commit private bundles, provider keys, router credentials, admin output, or sensitive packet captures.

Required live gates are Windows, macOS, Linux, Android and iOS/iPadOS physical network behavior; off-LAN methods; native visual/DPI QA; private server features; live AI providers; applicable Apple provisioning/signing/distribution; one deliberate exact-SHA production deployment; ASUS forwarding/JFFS fail-open revalidation; and final regression. Original requirement #339 qualifies macOS signing/notarization as optional polish when practical. The combined Apple gate's existing "where applicable" qualification preserves that scope; it does not waive legitimate iOS installation/provisioning or permit an unproved signing/notarization claim. See [the recovered source qualification](RECONCILIATION-2026-10-30-SOURCES.md#qualifications-and-attribution-corrections).

```bash
python3 deploy/live-release-evidence.py status release-evidence.json --sha <same-sha>
python3 deploy/live-release-evidence.py validate release-evidence.json --sha <same-sha> --require-final
```

A newer source commit means a new release SHA and a new live manifest. If a live test exposes a source defect, fix `main`, rerun the exact-head GitHub chain, and restart live evidence for the new SHA.

To include live proof in the weighted 88/12 release score, keep the manifest and raw proof outside Git and run the scorer against the already-green SHA:

```bash
export ROUTER_VPN_LIVE_EVIDENCE_MANIFEST=/private/evidence/release-evidence.json
export ROUTER_VPN_RELEASE_SHA=<same-40-char-sha>
python3 deploy/weighted-release-audit.py
```

Without both variables the manual/live gates deliberately remain false. The six weighted manual buckets cover all thirteen live gates: every shipping native platform, off-LAN methods, visual QA, private server features, live AI providers, applicable Apple distribution, the exact-SHA production deployment, ASUS fail-open forwarding revalidation, and final regression. A manifest for another SHA, an empty evidence list, or missing/tampered raw proof cannot award manual credit. The scorer's weighted metric is an implementation gate, not a percentage of the original requirements completed.
