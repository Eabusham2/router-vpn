# Ordered SS2022 datagram envelopes and tight native MTUs

This evidence concerns the supported local three-member chain: a paired WG,
AWG Fast or AWG Strong entry, one imported SS2022 middle, and a paired AES-256
SS2022 final node. It does not establish physical path MTU or installed OS TUN
acceptance.

## Codec sizes and what they mean

The pinned `sing-shadowsocks2 v0.2.1` client encodes the following additional
bytes for an unpadded UDP message with a literal destination. The mandatory
`TestRouterVPNDesktopNodeChainImportedSS2022Envelope` executes that codec and
checks all six entries using a 1252-byte application payload.

| SS2022 method | IPv4 destination | IPv6 destination |
| --- | ---: | ---: |
| AES-128-GCM | 50 | 62 |
| AES-256-GCM | 50 | 62 |
| ChaCha20-Poly1305 | 74 | 86 |

The independent `sing-shadowsocks v0.2.8` reference server's UDP reply header
contains an additional eight-byte remote session ID per SS layer. For example,
a 1252-byte payload through the paired AES final and an AES middle produces a
1380-byte IPv4 UDP packet inside WG/AWG on the request path and a 1396-byte
packet on the reply path. A ChaCha middle makes those packets 1404 and 1420
bytes. Those sizes include the enclosing IPv4/UDP headers and exclude the
physical WG/AWG ciphertext envelope.

These are datagram sizes, not TCP segmentation costs or an OS TUN ceiling.
The pinned native stack fragments and reassembles IPv4 datagrams. Subtracting
these numbers from every virtual packet would reject paths that actually
carry the datagrams successfully. Short DNS messages can also contain codec
padding; the numerical table intentionally describes unpadded messages.

## Required native delivery evidence

`TestRouterVPNDesktopNodeChainImportedMiddleTightMTU` constructs the real
native WG/AWG and SS outbounds and independent encrypted reference peers. It
recompiles the original first node's selected asset and independent identity
asset with an explicit MTU of 1280 or 1400. It does not edit a compiled endpoint
after capture. The server's actual WG/AWG stack MTU remains 1400, and the
captured shared virtual TUN remains 1280.

The matrix covers all three entry modes, all three imported SS2022 methods,
both tight first-interface MTUs, IPv4 and IPv6 application destinations, and
two payload sizes per destination:

- The UDP payload corresponding to the captured 1280-byte virtual packet:
  1252 bytes for IPv4 or 1232 bytes for IPv6.
- An explicit oversized native control corresponding to a 1500-byte virtual
  packet: 1472 or 1452 payload bytes. This control exercises native proxy
  datagram handling; it does not claim that the captured host TUN accepted a
  1500-byte packet.

Before the UDP checks, the fixture authenticates the original first private
health endpoint and checks its node proof. It then observes each real inner IP
packet at the reference WG/AWG device, before encryption and after decryption.
Every request and reply must arrive with identical application bytes. Every
observed IP fragment must have the exact expected length, offset and
more-fragments flag, and the complete set must reconstruct the cipher-specific
request or reply envelope. Observation order is allowed to differ, as real
packet delivery can reorder fragments.

The native matrix passed under the race detector. This includes fragmented
ChaCha replies whose complete 1420-byte inner packet exceeds the reference
interface's 1400-byte MTU, and oversized controls through 1280-byte entries.
The Linux installed-host runner executes both roots before its separate
installed namespace/TUN scenarios, requires all 134 exact verdicts, and
records the output digest. Its regression rejects omitted or duplicated
verdicts, failure, skip, panic, race diagnostics and unsuccessful execution.

## Deliberate limits

The encrypted reference uses IPv4 WG/AWG carrier addresses. IPv6 cases verify
application destination encoding and delivery through that carrier; they do
not establish IPv6-carrier fragmentation or a physical IPv6 path MTU. The
paired final remains AES-256. The client codec table directly checks ChaCha's
IPv6 address encoding, while the native chain's ChaCha middle uses an IPv4
next-hop address. Reply sizes for other address placements follow the pinned
server codec layout and are not additional physical measurements.

No production TUN ceiling, TCP policy, MTU controller, cache, Fixed setting,
Auto/Retest probe, cancellation or retained ownership rule changes in this
unit. Existing candidate-sized authenticated UDP probing still determines
live path behavior. Fragment delivery on an isolated native reference does
not guarantee delivery on arbitrary underlays, establish a nonfragmenting
path MTU, or replace the mandatory hosted installed-TUN and device gates.
