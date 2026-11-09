# Native Start Layer paired listener allocation

An exact native packet-reference run (`42410240765`, job `128518270528`,
source `92678123`) exhausted all three paired-listener attempts after the
UDP-selected ephemeral ports each collided with an existing TCP listener.
Choosing a UDP port does not reserve its TCP counterpart.

On Unix, the native layer fixture now asks TCP for port zero first and retains
that exact listener while binding UDP at its returned endpoint. If the UDP
counterpart collides, it closes only the captured partial owner and retries
within the unchanged three-attempt bound. Fatal errors, malformed returned
endpoints, and close failures remain failures. Both listener owners remain
captured until the complete pair joins cleanup. Windows retains its distinct
random-candidate policy and existing native address-in-use/permission handling.

The executable paired-listener inventory keeps all twelve prior allocation
controls, requires the production dispatch case, and adds ten Unix cases for
held TCP listeners, real UDP collisions and bounded exhaustion, fatal reads,
foreign endpoints, and exact partial-close failures. The production control
rejects the old dispatch. A second source counterfactual restores UDP-first
selection and fails the retained-TCP control.

Local validation on Go 1.26.3 passed all 25 race verdicts in a verbatim-source
projection, both intended source counterfactuals, and all 64 native runner
contracts (including their actual Go subprocess checks). The first runner
attempt selected the environment's unrelated `go` executable and did not run
four Go checks; the corrected PATH run passed all 64. The projection is not a
complete encrypted native-path pass. Current hosted packet-reference execution
still has to compile and exercise the actual prepared native package.
