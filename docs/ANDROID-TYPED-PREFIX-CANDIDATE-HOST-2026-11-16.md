# Android typed saved-prefix ownership — 2026-11-16

This change connects saved Local SOCKS5 and HTTP(S) CONNECT paths to the explicit closed packet-prefix factories. The complete typed source is retained as provenance; the temporary service starts only the selected WG/AWG packet prefix. The generic parser remains closed to typed source, and Server/Compare selection cannot silently start a Local test.

The Android service previously chose the full typed suffix factory even when a prefix purpose was present. Prefix startup now selects the neutral CommandServer first and binds only the prefix native owner. An unstarted suffix cannot supply a native close or partial-binding cleanup receipt. Retiring the prefix still requires its own original joined native receipt.

The existing required source and host gates now cover three-, four- and eight-node typed captures, actual Store/Load, full canonical source ownership, closed application/DNS/Ready state, prefix position/MTU proof rows, malformed readback, late source changes and cancellation. The AAR verifier requires both generated typed prefix factory signatures. The nine local ABI cases exercise that exact shell guard using explicitly synthetic javap text; they do not establish that an AAR has been generated.

## Local verification

| Gate | Executable checks | Compiled refusal controls |
|---|---:|---:|
| host-1 | 194 | 10 |
| source-1 | 693 | 9 |
| socks-1 | 204 | 6 |
| connect-1 | 654 | 6 |
| owner-1 | 53 | 8 |

All original controls remain, including the complete SOCKS/CONNECT native-receipt cases and the original prefix supervisor. Added controls restore the old suffix-first factory, substitute suffix cleanup authority, select the wrong source factory and remove exact purpose/source readback checks. Every gate retained its original child deadline and its complete required inventory.

The source capture gate executed the real Go compiler and shipping Java source. Service/runtime tests explicitly model Android OS and native interfaces. This does not prove installed-device permission, TUN/traffic/leak behavior or publication of the current native packages. The separately owned typed native dependency and the exact-SHA Android build remain required before declaring the shipping release accepted.

## Evidence identities

- Frozen source base: `5290bb69a778e7efbee0efc04e23380903195b3f` plus seven owned files and the separately recorded typed prerequisite.
- Owned manifest SHA-256: `d439d6e82564f22c90a232ddf623fccaaba330fab5e212027d48605acb00f91e`.
- Patch SHA-256: `468a6c12334c77b242ad0342368d83da361d8e3fed3a833a069dc1f9f3f18398`.
- host-1 log SHA-256: `daeb544f7fcd94fd62a05c3262b5fd79ea75930200d8c826d51da5b0d7616045`; receipt SHA-256: `44ed48bb9b9cbfa4becec3675eeaf0d79f9136f909592825bdb8ec14ef3fcbad`.
- source-1 log SHA-256: `6289cf7f5cc23e04399446eb333cfc4c6b2f21d330fa902f79375d20e97e088d`; receipt SHA-256: `f98c8e019d859f721896d2ac4b46b97a59b5a3339d0e0b52d8a530a50ec36cd6`.
- socks-1 log SHA-256: `9f0f5fd2b648e703d4cd8dbb928d4367d85eb73922fbbd188d0a89237cf15457`; receipt SHA-256: `bc98cdda53988039482da10f89466ff8e1388922718573fe16a69b17520b6207`.
- connect-1 log SHA-256: `71ab6f4cbe6fa593c4421c22b8e3997d37cf2bc3ca4c889417e9d18ab9d68d0a`; receipt SHA-256: `c3197503633833dd3924b2b5fb63505c7c6be0e01fc0c57dc4f5a2be79e1aff6`.
- owner-1 log SHA-256: `10efb60274146818906e7489172e3af7c213b214a40b7828bb470a86f95c8d65`; receipt SHA-256: `df0679f33b715f9498098c70ad7c330adc73071058bbc659d3686612380e1ae6`.

## Guarded integration

The local gates above ran on `5290bb69a778e7efbee0efc04e23380903195b3f` with the seven Android changes and the five explicitly borrowed typed production prerequisites. The completed source was then forwarded to published `d03b40c9eed6212334d9caa43d183138d928b817`. Every Android preimage and final body matched, and all five prerequisite bodies exactly matched their published versions. No borrowed implementation is replayed by this Android change.

The intervening shared change extends the separate Hysteria2 final-layer branch; the tested Shadowsocks and typed candidate branches are unchanged. The intervening desktop proposal and Apple changes are preserved. Local source and component evidence remain distinct from the required native bindings, exact-SHA Android package build and installed-device acceptance.
