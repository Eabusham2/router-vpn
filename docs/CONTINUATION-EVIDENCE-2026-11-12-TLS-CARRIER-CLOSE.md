# HTTPS carrier cancellation: close the original lower connection first

## Observed failure

Hosted run 43138281697, job 130919154614, source 35d79f3 failed
`TestRouterVPNImportedHTTPSRealityVisionNativeTraffic/off--aes-256-gcm+xor-whitening/cancel`.
The native final had already joined its retained streams and original physical
registry. The later XOR Start Layer owner cleanup returned:

```
tls: failed to send closeNotify alert (but connection was closed anyway):
write tcp4 127.0.0.1:37230->127.0.0.1:36135: i/o timeout
```

The log establishes an alert-write timeout, not which concurrent deadline setter
won that particular schedule. An earlier expired application write alone was
also tested and does not reproduce this alert failure: Go's alert write does not
simply return the stored application-write error. That hypothesis was rejected.

## Repair and scope

A concrete standard-library `*tls.Conn` returned by the captured detour now has
its exact `NetConn()` closed before TLS alert teardown. Both close results are
joined. The existing bounded error-tree classifier accepts only `net.ErrClosed`
leaves; it is unchanged. There is no timeout suppression, arbitrary wrapper
unwrapping, alternate dial, ownership replacement, or deadline increase.

This applies the existing physical-before-cipher teardown order to the TLS
carrier itself. Other connection types retain their existing close behavior.
Unknown TLS wrappers and real lower-close failures continue to fail cleanup.
The native default HTTPS client constructs a standard-library TLS connection;
a buffered CONNECT response can introduce a separate wrapper, which is not
implicitly unwrapped by this repair.

## Executed evidence

The new `TestCancelledOwnerJoinsExpiredTLSWriter` performs a certificate-verified
TLS handshake and an actual HTTP request/response over original loopback TCP.
Its lower writer then sets the actual socket deadline in the past immediately
before forwarding the TLS alert write. It never manufactures an I/O error. The
old implementation fails with the same `closeNotify ... i/o timeout` branch.
The repaired direct-TLS path closes the original socket first and joins cleanup.

Controls preserve an opaque carrier's actual alert timeout, a lower close that
fails without closing its descriptor, and a lower close that returns a timeout
while still open. The fixture independently verifies those descriptors remain
open until its own cleanup. Generic timeout and mixed closed-plus-timeout errors
also remain failures. Repeated Close, cipher release, key erasure, and rejection
of subsequent authenticated writes are checked.

- Complete `internal/startwhitening` race suite: PASS, 11.240 seconds.
- Existing retired-TLS test, new four-scenario real-TLS test, and complete strict
  close-error controls, ten race repetitions: PASS, 1.374 seconds.
- The existing exact native HTTPS cancellation leaf was attempted with captured
  shared source fixtures locally. It stops before traffic with
  `route ip+net: netlinkrib: operation not permitted`. This is not native
  acceptance; the hosted native gate remains required.

The physical macOS follow-up is separate: run 43140152150 at 0f1305a was still
pending/queued when this unit was completed. This change makes no PF deadline or
macOS ownership claim.
