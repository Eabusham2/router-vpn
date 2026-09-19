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

PASS is refused without at least one evidence file. The manifest stores each evidence file's SHA-256, size, source path and UTC capture time. It does not copy evidence into the repository, so do not commit private bundles, provider keys, router credentials, admin output, or sensitive packet captures.

Required live gates are Windows, macOS, Linux, Android and iOS/iPadOS physical network behavior; off-LAN methods; native visual/DPI QA; private server features; live AI providers; Apple signing/notarization/distribution; one deliberate exact-SHA production deployment; ASUS forwarding/JFFS fail-open revalidation; and final regression.

```bash
python3 deploy/live-release-evidence.py status release-evidence.json --sha <same-sha>
python3 deploy/live-release-evidence.py validate release-evidence.json --sha <same-sha> --require-final
```

A newer source commit means a new release SHA and a new live manifest. If a live test exposes a source defect, fix `main`, rerun the exact-head GitHub chain, and restart live evidence for the new SHA.
