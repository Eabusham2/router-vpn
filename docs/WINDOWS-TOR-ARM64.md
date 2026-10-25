# Windows ARM64 Tor helpers

Windows ARM64 can use Router VPN's Tor bridge implementation with the
checksum-pinned x64 standalone Tor process under Windows 11's built-in
userspace emulation. The Router VPN client, Go pluggable transports, sing-box
packet engine and VPN kernel driver remain ARM64. No x64 driver is installed
or emulated. The connection does not launch an external Lyrebird process.

The controller and installer use Microsoft's `GetMachineTypeAttributes` API
and require `UserEnabled` for `IMAGE_FILE_MACHINE_AMD64`. A missing API, query
failure or unsupported host does not become Ready. The installer verifies the
official Expert Bundle SHA-256, archive boundaries, unique helper files, and
bounded actual Tor and bundled Lyrebird version-process execution before
adoption. The Expert Bundle still contains Lyrebird; the active connection's
transport implementation comes from the separately pinned native Go package.

The capability API reports `helper_execution` so the compatibility path is not
mislabelled as ARM64-native Tor. Source package/pid/lifecycle ownership, private
configuration, strict firewall boundaries and dynamic Tor exit proof remain in
force; the selected bridges and cryptographic protocols are not substituted.
The wrapper assigns the native command's suspended child to an unnamed,
non-breakaway, kill-on-close Job before resuming it. Native SAFECOOKIE/PID
authentication, owned worker drain and actual child exit govern shutdown;
an exit code or wrapper receipt alone cannot declare a native tunnel closed.

The same-SHA release Windows matrix runs the actual Go host query and the
shipped installer's version checks on both x64 and Windows 11 ARM64. This proves
helper execution and packaging, not a live Tor circuit, leak test or device
acceptance. No Tor connection, driver or firewall is started by the smoke test.

## Sources and immutable runtime

- Microsoft Windows on Arm emulation: https://learn.microsoft.com/en-us/windows/arm/apps-on-arm-x86-emulation
- Machine capability API: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getmachinetypeattributes
- Expert Bundle 15.0.24 / Tor 0.4.9.13: https://dist.torproject.org/torbrowser/15.0.24/sha256sums-signed-build.txt
- Windows x86_64 SHA-256: `e9dc6ccc93cd6afa507193f4de284d6424233ff5102155cd2c94b259e8a22b65`.
