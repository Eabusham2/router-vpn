package mobiletor

import (
	"context"
	"errors"
	"os"
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
// an error. File or Native must be an actual unbound, unconnected kernel socket;
// the broker imports that socket without recreating one under its own identity.
type DesktopSocketCreated struct {
	Creation DesktopSocketCreation
	File     *os.File
	Native   DesktopSocketNative
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

// DesktopSocketTunnelPolicy is the OS firewall adapter whose tunnel permit
// depends on a real interface identity. The native Box supplies its own TUN
// readback and retires that permit before a serialized device replacement.
// Linux's name-bound baseline does not need this additional WFP lifecycle.
type DesktopSocketTunnelPolicy interface {
	BindTunnel(context.Context, DesktopSocketCapture, string, uint32) error
	RetireTunnel(context.Context, DesktopSocketCapture, string, uint32) error
}

func (s *desktopSocket) create(ctx context.Context) error {
	if s.broker.source == nil {
		return nil
	}
	request := DesktopSocketCreation{Capture: s.broker.capture, Binding: s.binding, SocketID: s.id, Network: s.network}
	bounded, cancel := context.WithTimeout(ctx, desktopSocketControlWait)
	reply, err := s.broker.source.CreateSocket(bounded, request)
	deadlineErr := bounded.Err()
	cancel()
	// Publish ownership before checking the result, including cancellation and
	// malformed metadata. drain waits for this operation before releasing it.
	s.mu.Lock()
	s.sourceFile = reply.File
	s.sourceNative = reply.Native
	s.mu.Unlock()
	if err != nil || deadlineErr != nil || ctx.Err() != nil || !s.live() || (reply.File == nil) == (reply.Native == nil) || reply.Creation != request {
		return errors.Join(err, deadlineErr, ctx.Err(), errors.New("desktop physical socket creation lost its exact captured owner"))
	}
	return nil
}
