# Hosted Naive HTTP/2 native reference, November 26

The [original workflow](https://github.com/Eabusham2/router-vpn/actions/runs/45726058736)
completed both jobs successfully at source
`d887c3006adbf195e1c2758fc87f1b90abf2e9fa`.
The native reference job is
[139623050336](https://github.com/Eabusham2/router-vpn/actions/runs/45726058736/job/139623050336).

The unmodified native JSON receipt records 81 shared graph exports and 659
required root/leaf verdicts: 365 proxy and 294 packet cases. Both native roots
used executable SHA-256
`9597e4ce6ddc13c4cb8504ae4a4507ad45417e87fc3f71b414b70a144a02bb51`.
The native Cronet library was 11,915,768 bytes, SHA-256
`23109c55b08829bb1a68682a61a64852b1bbf243753b153cbd8f6e4ea2c05294`.

This completes the previously blocked reference proxy and packet cases. The
receipt explicitly describes captured reference tuples, without OS TUN
acceptance, and marks installed-device and production-router acceptance false.
It does not establish physical-interface or installed-client acceptance.

`native-receipt-0.json` is the original JSON line from the hosted job, with only
the GitHub log timestamp removed and a final newline added. The complete job
log as returned by the GitHub connector is retained losslessly as gzip; its
UTF-8 SHA-256 and size are in `provenance.json`. The broader log also contains
other required stages, so its count of Go pass events is not the native
reference receipt's 659-verdict inventory.

The original Apple graph ZIP artifacts were verified against GitHub's published
SHA-256 values: artifact 15077868365 (`fd178b3622d6b14a974a3ef285afd3cf5e9ee40dd8ca328466354d232f27f788`)
and artifact 15078356570 (`d2161b7033ad6f0d1000e5ef5a1f752140cc2d664aaf37a3483f1410e2e3eef7`).
All retained local files have hashes in `SHA256SUMS`.

The final release must still complete its mandatory native and packaging gates
on the exact revision that the release publishes.
