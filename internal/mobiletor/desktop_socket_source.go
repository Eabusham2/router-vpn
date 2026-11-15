package mobiletor

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"runtime"
	"syscall"
)

// DesktopSocketCreation binds a transferred descriptor to the same immutable
// owner that will install its physical permit. A reply never supplies a new
// capture, network, socket identity or interface on the caller's behalf.
type DesktopSocketCreation struct {
	Capture  DesktopSocketCapture
	Binding  DesktopSocketBinding
	SocketID string
	Network  string
}

// DesktopSocketCreated transfers ownership even when CreateSocket also returns
// an error. File or Native must be an actual unconnected kernel socket. Sources
// supply it unbound except the closed Darwin Off capability, whose original
// creator-bound tuple and kernel object are independently rechecked on import.
// The broker imports that socket without recreating one under its own identity.
type DesktopSocketCreated struct {
	Creation DesktopSocketCreation
	File     *os.File
	Native   DesktopSocketNative
	prebound *desktopSocketPrebound
}

// This capability has no exported constructor or fields. Only the concrete
// Darwin Off owner may attach it after binding, state inspection and actual
// creator/socket readback. Exported metadata cannot authorize a bind bypass.
type desktopSocketPrebound struct {
	source   DesktopSocketSource
	creation DesktopSocketCreation
	local    netip.AddrPort
	verify   func(*os.File) error
}

func (p *desktopSocketPrebound) validate(source DesktopSocketSource, creation DesktopSocketCreation, file *os.File) error {
	if p == nil || runtime.GOOS != "darwin" || p.source == nil || p.source != source || p.creation != creation ||
		file == nil || p.verify == nil || !p.local.IsValid() || p.local.Port() == 0 || p.local.Addr() != creation.Binding.LocalAddress {
		return errors.New("desktop prebound socket lost its closed original Darwin authority")
	}
	return p.verify(file)
}

func desktopSocketCapturedPrebound(captured []*desktopSocketPrebound) (*desktopSocketPrebound, error) {
	if len(captured) > 1 {
		return nil, errors.New("desktop socket import mixed prebound authorities")
	}
	if len(captured) == 1 {
		return captured[0], nil
	}
	return nil, nil
}

// DesktopSocketNative retains an OS socket that cannot be closed as an os.File.
// Winsock handles require closesocket, and their imported I/O must retain that
// same endpoint instead of constructing a new socket under the receiver token.
// Exactly one of File and Native may be supplied. Both are retained and closed
// on a malformed or cancelled creation reply before the source can retire.
type DesktopSocketNative interface {
	SyscallConn() (syscall.RawConn, error)
	Close() error
}

// DesktopSocketSource is an optional capability of the independently created
// OS policy, not a configuration flag or an alternate caller-provided dialer.
// An OS policy uses it to create sockets under its isolated identity without
// moving the native TUN/route owner into that identity. A Unix descriptor and a
// Winsock handle keep their own import and close primitives.
//
// CreateSocket must join its transfer before returning. Any received descriptor
// belongs to the caller, including an invalid or late reply returned with an
// error. Independently validating the real socket's kernel creator belongs to
// Bind/Grant; a helper's UID metadata is never a substitute for that readback.
// Cancel revokes pending creation immediately. Close is bounded and retryable,
// and succeeds only after every creator process and descriptor transfer joined.
// The policy must quarantine its isolated identity until broker Close has also
// removed all permits and closed all returned/duplicated kernel descriptors.
type DesktopSocketSource interface {
	CreateSocket(context.Context, DesktopSocketCreation) (DesktopSocketCreated, error)
	Cancel()
	Close(context.Context) error
}

// A privileged guardian may retain a second socket handle outside the native
// process. ReleaseSocket runs only after exact permits are absent and every
// native I/O/descriptor has joined. An unknown result remains retryable and
// does not free the independently owned identity for another socket.
type DesktopSocketSourceRelease interface {
	ReleaseSocket(context.Context, DesktopSocketCreation) error
}

type desktopSocketAdmittedSource interface {
	createSocketAdmitted(context.Context, DesktopSocketCreation) (DesktopSocketCreated, error)
}

type desktopSocketAdmittedSourceRelease interface {
	releaseSocketAdmitted(context.Context, DesktopSocketCreation) error
}

func desktopSocketCreateControlled(ctx context.Context, source DesktopSocketSource, request DesktopSocketCreation) (DesktopSocketCreated, error) {
	if admitted, ok := source.(desktopSocketAdmittedSource); ok {
		return admitted.createSocketAdmitted(ctx, request)
	}
	bounded, cancel := context.WithTimeout(ctx, desktopSocketControlWait)
	defer cancel()
	reply, err := source.CreateSocket(bounded, request)
	return reply, errors.Join(err, bounded.Err())
}

func desktopSocketReleaseControlled(ctx context.Context, source DesktopSocketSourceRelease, request DesktopSocketCreation) error {
	if admitted, ok := source.(desktopSocketAdmittedSourceRelease); ok {
		return admitted.releaseSocketAdmitted(ctx, request)
	}
	bounded, cancel := context.WithTimeout(ctx, desktopSocketControlWait)
	defer cancel()
	return errors.Join(source.ReleaseSocket(bounded, request), bounded.Err())
}

// DesktopSocketTunnelPolicy is the OS firewall adapter whose tunnel permit
// depends on a real interface identity. The native Box supplies its own TUN
// readback and retires that permit before a serialized device replacement.
// Linux's name-bound baseline does not need this additional WFP lifecycle.
type DesktopSocketTunnelPolicy interface {
	BindTunnel(context.Context, DesktopSocketCapture, string, uint32) error
	RetireTunnel(context.Context, DesktopSocketCapture, string, uint32) error
}

// A name-bound OS filter also retains the actual TUN control object. Darwin
// utun names are reusable after the final descriptor closes; a guardian-held
// duplicate prevents a replacement interface from acquiring a live permit.
// The caller retains its file until this synchronous transfer returns.
type DesktopSocketTunnelFilePolicy interface {
	DesktopSocketTunnelPolicy
	BindTunnelFile(context.Context, DesktopSocketCapture, string, uint32, *os.File) error
}

func (s *desktopSocket) create(ctx context.Context) error {
	if s.broker.source == nil {
		return nil
	}
	request := DesktopSocketCreation{Capture: s.broker.capture, Binding: s.binding, SocketID: s.id, Network: s.network}
	reply, err := desktopSocketCreateControlled(ctx, s.broker.source, request)
	// Publish ownership before checking the result, including cancellation and
	// malformed metadata. drain waits for this operation before releasing it.
	s.mu.Lock()
	s.sourceFile = reply.File
	s.sourceNative = reply.Native
	s.sourcePrebound = reply.prebound
	s.mu.Unlock()
	if err != nil || ctx.Err() != nil || !s.live() || (reply.File == nil) == (reply.Native == nil) || reply.Creation != request {
		return errors.Join(err, ctx.Err(), errors.New("desktop physical socket creation lost its exact captured owner"))
	}
	if reply.prebound != nil {
		if err := reply.prebound.validate(s.broker.source, request, reply.File); err != nil {
			return err
		}
	}
	return nil
}

// DesktopSocketLeaseCleanup is an original native capability, never a host
// boolean. Sealing is inert; terminal quiescence is irreversible and keeps the
// same physical control transport while independently proving data permits gone.
type DesktopSocketLeaseCleanup interface {
	Quiesce(context.Context, string, uint32) error
	Current(context.Context) error
	Discard()
}
type DesktopSocketLeaseCleanupPolicy interface {
	SealLeaseCleanup(context.Context, DesktopSocketCapture) (DesktopSocketLeaseCleanup, error)
}
