# Exact native engine authority for ordered MTU

The shared ordered MTU pause binding now exposes `OwnsEngine`, an observation of its retained private engine pointer. The actual native `closedMTUContext` requires that exact pointer before replacing or admitting a reader. Equal reported session/source/configuration identities, or another adapter delegating observations to the original engine, cannot substitute for ownership.

The native adapter introduced in `55ee21293ed556aa4dd89102656f8bee961f7f1f` is preserved. This change adds one ownership condition and a causal regression to that adapter. It does not replace its actual manager transaction, native interface readback, ingress transfer, retained execution selection, or joined retirement. The independent earlier incomplete adapter draft was superseded and was not applied over upstream.

## Executed evidence

- The shared runtime pause/resume receipt test passed with `-race` in 2.968 seconds. It accepts the original pointer and refuses nil, typed nil, a different pointer, an underlying delegated engine, a non-comparable value wrapper, and a zero binding without panicking.
- The actual pinned native Box, inbound manager, selector, gate and ingress MTU component checks passed with `-race`: four roots and 22 required results. These cover candidate, rollback, unchanged and pending-close transactions; original source, reader, bounds and selected execution; joined retirement; and bounded real-TUN readback refusal.
- The new native case keeps the same valid closed capsule and reported identity but substitutes another engine wrapper. It must refuse before native acquisition. Removing only `binding.OwnsEngine(e)` compiles and reaches the intended `changed ownership acquired native MTU transaction` assertion; a compilation error or data race is not accepted as this causal result.

The native run used an explicit three-file Go overlay on the freshly prepared Last-adoption core documented in `CONTINUATION-EVIDENCE-2026-11-12-NATIVE-LAST-ADOPTION.md` (strict baseline digest `cdd7fb09026ef9acf35c6704a9aea16acfab1117842cc126b62365d5259ed4a8`). The overlay supplied the generated shared method, native guard and native test. The original prepared files and their receipt remained byte-identical. This is a scoped component result, not a claim that the frozen core contains every subsequent main-branch change.

The mandatory owner runner retains its exact anchored root selection and all Last/MTU/close cases. Its complete current inventory is 20 roots, 54 required results and 14 causal controls; all seven runner boundary tests pass after integration. Full native and release CI must still execute this integrated source. The component TUN readback and shared closed-pause capsule are explicit fixture boundaries; this does not establish a physical device session or private deployment.
