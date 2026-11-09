# Protected desktop imported policy

`DesktopImportedPolicy` is a separate sealed adaptation of the original
`NewImportedEntry` constructor. It retains the complete private imported entry
and independently paired final. It does not synthesize a `NodeProfile` or an
ordinary external final policy. The current native target is Windows.

The private launch envelope replays all seven exact original inputs. The
derived source binds the original source/configuration/metadata/envelope
digests, session, target, both identities and modes, both Start Layers, final
protection policy, combined IPv6/LAN constraints, physical root identities and
any captured TUN MTU restoration value. Rehashing edited output cannot replace
rederivation from those inputs.

The final owns application DNS. Its selected resolver remains routed through
`proxy`; only actual captured physical bootstrap dependencies acquire the
native lower detour. The entry public-path proof has its own loopback listener
on 1098 routed to `entry-wg`. The paired-final proof has its own loopback
listener on 1099 routed to `proxy`. Neither listener grants a successful proof.

Only original physical roots receive the native lower detour. When a direct
SOCKS5 entry needs a negotiated UDP relay, the derived graph names a distinct
retained imported SOCKS type. The static root contains only its exact TCP
control tuple. A TCP-carried REALITY final does not invent a UDP relay. An
authenticated per-operation native association remains required for actual
dynamic UDP admission.

The shared `DesktopPhysicalPolicy` interface is limited to the independently
sealed node/imported constructors. `ReadDesktopPhysicalPolicy` checks concrete
types, including rejecting a caller-defined interface wrapper. The native
readiness record still describes only fresh selected-DNS exchange and TUN
readback. The parent owes the separate imported-entry public-path and paired
final proofs before reporting Connected.

## Executable shared verification

The focused race run on the original seven-input replay plus this adaptation
passed 16 root tests and 507 individual/root verdicts, with no failures or
skips. It ran with Go 1.26.3:

```sh
go test -race -json ./internal/mobilemultihop \
  -run '^(TestImportedLaunchInput|TestDesktopImportedPolicy|TestDesktopNode(Policy|Ready|Read)|TestImportedDesktopPhysical)' \
  -count=1 -timeout=120s
```

Coverage includes nine original entry wire kinds across independent Off/AES/
AES+XOR layers and a paired REALITY/Vision final, plus SS, Hysteria2, WG and both
AWG finals. The full adapted graph is compared against the original after
removing only the exact declared native adaptation. Separate cases exercise
final selected encrypted DNS, entry/final device policy, captured MTU restore,
distinct replay/restoration owners, returned-copy isolation, missing authority,
altered and rehashed proof/configuration/source, closed or network-invalidated
originals, and retained existing Node policy/readiness contracts.

This shared verification does not establish that a native child has installed
WFP policy, authenticated its journal parent, executed both encrypted hops,
restored a physical device connection or passed a release build. Those are
separate native composition and acceptance boundaries.
