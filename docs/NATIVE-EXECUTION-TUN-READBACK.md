# Native ordered execution TUN readback

The shared ordered execution runtime requires an effective native TUN observation
when attaching MTU control or capturing mobile restoration. The native engine
implements that capability in `mobile/chain/execution_readback.go.tmpl`.

## Retained identity and retirement

Capture observes the original active reader through the real TUN's bounded
readback method. It retains the original Box, execution identity, gate control,
reader generation, interface name, interface index, and effective MTU. An unchanged
reader retains its random nonce. An authorized reader replacement receives a new
nonce and generation; an earlier capture cannot describe the replacement.

The application gate and original execution must remain current before and after
the native observation. A changed interface or non-cancellation read failure
invalidates an existing capture permanently and revokes application admission.
Restoring old OS values cannot restore that capture. Ordinary caller cancellation
does not itself invalidate a current reader.

Retirement is recorded only after the exact engine has joined its owned stops,
closed its gate, and retired its ingress. A successful restore receipt additionally
requires the actual original `Box.Close` result. The early `Box.done` signal and a
caller-created readback value cannot substitute for it. The receipt remains
queryable after host teardown without querying destroyed managers or the OS;
an original native close error remains an error.

## Verification boundary

The native component tests exercise the real pinned managers, selector, gate,
discovery, reader transaction, and `Box.Close`. Privileged TUN readback and encrypted
transport remain explicit test boundaries. The public readback method rejects the
fixture TUN. These tests do not establish physical-device MTU, network-transition,
or leak acceptance.

## Recorded execution

- The complete native owner inventory passed with the race detector: 31 roots
  and 98 root/child verdicts across the Box, TUN, and outbound-manager packages.
  Their package execution times were 38.593, 1.105, and 1.017 seconds.
- Removing the actual close join failed at the original-close assertion.
  Removing exact issued-value equality failed at the forged-observation
  assertion. Both controls executed the real compiled native adapter.
- All seven verdict-parser checks and nine preparation checks passed.
- The prepared core was pinned to
  `1ac1a339cb1223e9c70eae14c44411c75033c02d`. This local run used explicit
  current-owner overlays on the officially prepared `01cc839` desktop core;
  the owner sources included the `0765d62` Last-adoption changes and this unit,
  based on `a683e62`. All 5,146 original core files remained byte-identical
  before and after execution. No manifest was changed to bless an overlay.
- The hosted native runner retains its full inventory and all 21 causal
  controls, including the two new controls above. Only those two newly added
  controls are claimed as executed in this focused local run.
