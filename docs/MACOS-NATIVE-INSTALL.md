# Native macOS installation and controller ownership

## Install and open the app

Download the native archive for your Mac, verify its release checksum, and
extract the complete directory. Run `./install-router-vpn.sh` from your normal
Mac account and approve its administrator request. The installer places the
application and its prebuilt engines together under `/opt/router-vpn-client`.
Open `RouterVPN.app` from your user Applications folder; this entry points to
the protected installed app. Import or link private router information
separately from the generic application package.

The protected platform helpers require Python 3.9 or newer from a root-owned
Apple Command Line Tools installation or the signed
[Python.org macOS installer](https://www.python.org/downloads/macos/). Before
executing Python with privilege, the native installer checks the interpreter,
its installation tree and parent directories, including native ACL grants that
are independent of Unix mode bits. A user-writable interpreter or
library installation cannot provide the privileged runtime. The installer uses
the packaged VPN engines without compiling replacements on the Mac.

The staged application, native runtime receipts and code signatures are
verified before installation is promoted. Existing download quarantine is
preserved. Ad-hoc signatures establish package integrity; Developer ID signing,
provisioning where applicable and notarization remain separate distribution
requirements. Keep Gatekeeper enabled.

## Upgrade, preservation and recovery

Close Router VPN and wait for its owned controller and engines to finish
cleanup before upgrading. The live controller retains a shared installation
lock. The installer requires the exclusive lock before reading launchd state
or replacing files, and also checks actual executable paths for older
processes that do not implement the lock protocol.

Installation copies code into fresh root-owned files. Linked private nodes,
settings, generated private material and the original authorized desktop user
are preserved. An open descriptor to an old code file cannot rewrite the new
installation. The generic archive cannot replace the installation's private
owner record.

If promotion or launchd integration fails, the transaction restores the old
installation and service definition. If restoration itself fails, it retains
the recovery directory and reports its path. Another installation is refused
until that interrupted transaction is resolved; do not delete the retained
private state merely to bypass the error.

An older unauthenticated controller service must be deliberately stopped and
removed before migration. The installer refuses an unrecognized service under
the Router VPN label instead of terminating an active tunnel whose owner it
cannot establish. The original full-bundle recovery scripts remain available;
when given a complete native package they use this native installation path.

## How the installed application owns its controller

The AppKit interface runs as the desktop user. A fixed root-owned launchd
supervisor accepts a private Unix socket connection only from the user recorded
by installation. The two sides validate native peer credentials and process
identity. Fresh controller access and ownership secrets are transferred over
that captured connection, never through command-line arguments or a public
configuration file.

The supervisor socket is `/opt/router-vpn-client.control/controller.sock`.
Both peers inspect its complete root-owned directory and ACL ancestry. The
system's `/private/var/run` directory may grant group write permission, so it
does not supply this application's protected runtime authority; the installer
does not change that system directory's permissions.

The supervisor holds the installation and controller locks before starting the
fixed controller. Their inherited descriptors and the accepted owner socket
remain tied to that child. The app verifies an authenticated startup receipt
before releasing API credentials. Normal requests, connection progress, DNS,
MTU, Speed Lab and shutdown retain that same captured controller authority;
redirects cannot transfer it to another endpoint.

Losing the owner connection revokes the child's authority and initiates owned
shutdown. The supervisor's completion receipt follows waiting for that exact
child. A missing receipt or a crash is not reported as successful clean
shutdown. Developer launches from extracted folders remain a separate
unprivileged path.

The supervisor reasserts a saved Always protection policy before exposing its
listener. Its launchd `RunAtLoad` setting alone does not establish that network
traffic was blocked before every network service started during boot; that
requires macOS boot and leak acceptance evidence.

## Verification boundaries

`deploy/test_macos_native_install.py` executes real file transactions in
temporary installation roots, with strict doubles for host service and
firewall operations. It covers preservation, fresh files, active-owner refusal,
legacy service/process refusal, failed verification, rollback and retained
recovery. Production mutations must be rejected by the corresponding cases.
Its `--package` mode additionally runs the actual matching-architecture bundled
runtime and signature verification through installation and upgrade.

`deploy/test_macos_installer_trust.py` exercises actual root ownership and file
permissions for the interpreter checks. On macOS both installer test runners
also create and remove ACLs on their own temporary fixtures, proving that
extra write grants and private-data read grants are rejected while ordinary
public read and deny-only system ACLs remain usable. Cross-compilation and these isolated
tests do not establish macOS permissions dialogs, real network transitions,
selected-path traffic, leak behavior or physical visual acceptance. Native
supervisor and application gates must also pass on the exact release source.

Platform references: Apple's [launchd job documentation](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html),
[launchctl bootstrap and bootout examples](https://it-training.apple.com/compliance/tutorials/course/sec050/),
and [libproc process identity implementation](https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/libproc/libproc.c).
