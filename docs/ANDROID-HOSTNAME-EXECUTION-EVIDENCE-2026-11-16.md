# Android hostname execution editor evidence — November 16, 2026

The Android ordered-path editor previously applied numeric-address parsing to every imported Server or Compare member. That prevented a saved Shadowsocks 2022 hostname from reaching the already implemented shared execution compiler.

`AndroidOrderedPathSelection.requireBound` now admits the original hostname only in the penultimate Shadowsocks position of a schema-two path with four to eight members. It reuses `AndroidStandardExitStore.validateImportedHostnamePolicy`, requiring the original Custom TCP resolver, explicit canonical resolver IP and port, and valid saved SS2022 credentials. A three-member hostname path remains rejected before changing the saved execution. Other imported protocols retain strict numeric-address parsing.

## Executable evidence

The existing required `android/test_android_imported_prefix_execution_capture.py` gate ran the shipping Java editor callbacks, stores, Add/Load/Update/Delete profile transactions and source captures against the actual shared Go compiler. All nine original phases remain. Four added hostname phases cover the four- and eight-member bounds, all three SS2022 methods, Server/Compare choices, selected transport DNS versus final Home DNS, saved resolver restoration, later-prefix replacement and malformed source readback.

The complete run passed 13 phases with 3,742 reported source/profile checks and seven compiled causal controls. The controls retain the original node-store, editor, returned-size, member and identity witnesses, and additionally restore numeric-only hostname admission or remove the four-member minimum. Each modified program failed at its intended assertion.

The source run used base `163c80fdc328d7677f617a271a492b234aa9d9e1` plus the two-file source patch with SHA-256 `ada3d1772ee642e21a39a771d6ed604fdd74f1c7b63b3a6801d3d75167220e69`. Source bytes were unchanged throughout the run. The full gate completed in 720.79 seconds, retaining the existing 120-second Java phase limits and 15-minute enclosing budget. Its log SHA-256 is `a22ba2f9913884fc036bdb16da7d0593f99c7d939c0181cafee62c7747c8073c`.

The local toolchain was Go 1.26.3 with Java 17 and the real Android JSON implementation. Initial attempts stopped at missing local JSON/JDK setup and are retained separately; they are not product failures or successful execution evidence.

## Evidence boundary

This gate compiles actual original source and exercises the shipping Java product path. Native Run, leases, TUN and restoration capsules are explicit refusing boundaries. It does not establish device networking, encrypted traffic, Android permission behavior, APK publication or private deployment. Those remain separate native/release/device gates. This change does not expand HTTP/HTTPS CONNECT or SOCKS source bounds.
