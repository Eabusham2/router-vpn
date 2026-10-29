# Native Linux installation and permissions

Use the exact-SHA Linux package for the machine's architecture. The published
native jobs run on matching x64 and ARM64 Linux hosts. The installer uses
systemd for persistent client protection and polkit for the administrator
request. It checks the actual GTK application's linked libraries before
replacing an existing installation.

## Install and open

Verify the release checksum, extract the package, and run its installer:

```sh
sudo ./install-router-vpn.sh
```

Close an existing Router VPN window and wait for its tunnel cleanup before
upgrading. A legacy `router-vpn-client.service` must also be stopped before
upgrading; the installer refuses to replace a running controller. It preserves
linked nodes, credentials, generated node files, saved settings and connection
state. A generic package contains no linked private node.

Open **Router VPN** from the desktop application menu using your normal user
account. Approve the system's administrator request for the Router VPN
connection controller. The GTK window stays under your desktop user. The
controller needs administrator access for the device tunnel, routes and client
protection. Do not run the GTK window with `sudo`.

If the authorization dialog is cancelled, the app does not connect. If another
window or application owns the local controller port, close that instance
before starting a new one. The app verifies its launched controller's identity
before sending API credentials; an unrelated listener is not reused.

The installer can obtain missing runtime dependencies from configured
Debian/Ubuntu repositories. Other distributions must provide compatible GTK3,
libcurl, json-glib, Python 3, nftables, iproute2, the shadow account tools,
`nologin`, pkexec/polkit and systemd. No VPN engine is compiled during normal
installation. Check dependencies without installing them with:

```sh
bash client/install-linux-system-tools.sh --check ./router-vpn-app
```

An installed package uses the protected `/opt/router-vpn-client` location.
Extracting another copy does not give that copy administrator authority.

## Close, upgrade and recover

Closing the window requests cleanup of its captured connection and waits for
the controller to finish. If cleanup is still pending, the window explains that
state. A stopped or failed child is not treated as proof that its tunnel and
leases have drained. If the GUI disappears unexpectedly, its anonymous lifetime
pipe closes and the controller begins the same owned cleanup.

Route registration starts no automatic connection. Saved autoconnect is
scheduled only after the controller owns its listener and shutdown lifetime.
An already-closed lifetime rejects both a previously captured startup and new
authenticated requests immediately, before asynchronous cleanup runs.

The installer holds an exclusive installation lock. A running authenticated
controller holds the shared lock until exit, so an upgrade cannot replace its
code or private state. New code and runtime files are copied into private,
root-owned staging with fresh inodes and verified before promotion. A write
handle to an old user-owned file cannot alter the newly installed file.

Failed promotion or system integration restores the previous installation and
owned system files. If rollback cannot finish, recovery material is retained
and the installer reports its exact location. A later attempt refuses to
discard an interrupted installation's backup. Resolve that reported recovery
state before attempting another upgrade.

## Always protection at boot

The native installer supplies `router-vpn-killswitch-early.service`. It reasserts
the saved client Always policy before networking starts. The installed
NetworkManager, systemd-networkd, Debian networking, ConnMan and wicked
dependency drop-ins require that service to succeed before those managers can
start. An Off policy returns successfully without imposing an Always block.

Installation reasserts the saved policy and starts an inactive early service.
It does not restart that dependency beneath already-running network managers.
The ordinary root HTTP controller is not started as a boot service.

For local emergency recovery:

```sh
sudo router-vpn-killswitch-recovery
```

This operates only on Router VPN's client protection using the fixed installed
helper. Review the saved policy before rebooting, because a saved Always choice
will be reasserted again. This client protection is separate from the ASUS
forwarding helper's household fail-open behavior.

## Implementation and verification

The administrator entry point accepts only `--linux-owned-controller` at its
fixed installed executable. It validates root ownership, permissions, file
identity, fixed loopback configuration, the invoking desktop UID, and the
anonymous input pipe. The 256-bit API credential and separate shutdown owner
are supplied through that pipe, never through argv, environment, public status
or discovery files. A challenge/response binds startup to the fresh challenge
and retained child PID before the GUI sends its bearer credential. Every
privileged HTTP handler, including reads and shutdown, checks authorization,
the expected loopback host/peer and browser-origin restrictions.

The normal root startup of that installed executable is rejected. Standalone
runtime verification commands keep their read-only utility ordering. Source
development and the other native platforms retain their existing startup paths.

The mandatory Linux packaging gate hashes the current source, compiles its
privilege tests with race instrumentation, and runs the actual fixed-installed
bootstrap in private user/PID/mount/network namespaces. Its cases include real
non-root pipe ownership, five-second input expiry, both lock types, secret
nonpublication, EOF/second-message retirement, invalid installations and the
actual `main()` refusal of unauthenticated root startup. GTK tests execute the
real launch and shutdown callbacks with explicit process/authentication
boundaries. Installer tests execute real staging, promotion, permissions and
rollback in temporary roots, with systemd/firewall subprocesses doubled.

Package jobs additionally verify the actual bundled native, Amnezia and Xray
runtimes through installation and upgrade. These tests do not establish an
interactive polkit prompt, a physical reboot, a public VPN/Tor circuit, or
device leak/reconnect acceptance. Those remain separately recorded live gates.

Primary platform references:

- [polkit pkexec authorization and environment](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [systemd network-pre target](https://www.freedesktop.org/software/systemd/man/latest/systemd.special.html)
- [systemd requirement and ordering dependencies](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html)
