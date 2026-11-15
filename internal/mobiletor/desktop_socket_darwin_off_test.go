//go:build darwin && routervpn_darwin_guardian

package mobiletor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func desktopDarwinOffKernelPolicy(t *testing.T, network string, remote netip.AddrPort) *DesktopDarwinSocketPolicy {
	t.Helper()
	capture := desktopSocketFixtureCapture()
	options := desktopDarwinKernelOptions(t, []DesktopDarwinSocketDestination{{Network: network[:3], Address: remote}})
	options.HostProtectionOff = true
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if err := desktopDarwinPFLoad(ctx, desktopDarwinPFNamespace, desktopDarwinPFBaseline(capture, options)); err != nil {
		t.Fatal(err)
	}
	policy, err := NewDesktopDarwinSocketPolicy(context.Background(), capture, options)
	if policy != nil {
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			if err := policy.Close(ctx); err != nil {
				t.Error("original Darwin Off guardian did not retire", err)
			}
		})
	}
	if err != nil {
		t.Fatal("actual Darwin Off guardian preparation", err)
	}
	if !policy.options.HostProtectionOff || policy.pf.Baseline != strings.TrimSpace(desktopPFIsolatedBaseline(capture.SessionID)) ||
		!policy.pf.pointerValid() || !strings.Contains(policy.pf.Pointer, "block drop out quick") {
		t.Fatal("Darwin Off baseline lost its dispatch-only root and independent UID deny")
	}
	return policy
}

func desktopDarwinOffHostExchange(t *testing.T, network string, remote netip.AddrPort) {
	t.Helper()
	local := desktopDarwinTestFixture.Addresses[0]
	if remote.Addr().Is6() {
		local = desktopDarwinTestFixture.Addresses[2]
	}
	dialer := net.Dialer{}
	if strings.HasPrefix(network, "udp") {
		dialer.LocalAddr = net.UDPAddrFromAddrPort(netip.AddrPortFrom(local, 0))
	} else {
		dialer.LocalAddr = net.TCPAddrFromAddrPort(netip.AddrPortFrom(local, 0))
	}
	ctx, cancel := context.WithTimeout(context.Background(), desktopSocketControlWait)
	defer cancel()
	connection, err := dialer.DialContext(ctx, network, remote.String())
	if err != nil {
		t.Fatal("Darwin Off blocked an unrelated ordinary host socket", err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	message := []byte("unrelated ordinary host remains usable")
	if _, err := connection.Write(message); err != nil {
		t.Fatal("Darwin Off blocked an unrelated ordinary host socket", err)
	}
	body := make([]byte, len(message))
	if _, err := io.ReadFull(connection, body); err != nil || string(body) != string(message) {
		t.Fatal("Darwin Off blocked an unrelated ordinary host socket", err)
	}
}

func TestDesktopDarwinGuardianKernelOffHostAndBroker(t *testing.T) {
	for _, network := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
		t.Run(network, func(t *testing.T) {
			remote := desktopDarwinKernelPeer(t, network)
			policy := desktopDarwinOffKernelPolicy(t, network, remote)
			desktopDarwinOffHostExchange(t, network, remote)
			broker := desktopDarwinKernelBroker(t, policy)
			ctx, cancel := context.WithTimeout(context.Background(), desktopSocketControlWait)
			connection, err := broker.DialContext(ctx, network, remote.String())
			cancel()
			if err != nil {
				t.Fatal("Darwin Off original prebound broker did not acquire its exact permit", err)
			}
			desktopDarwinExchange(t, connection)
			if err := connection.Close(); err != nil {
				t.Fatal(err)
			}
			closeCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if err := broker.Close(closeCtx); err != nil {
				t.Fatal("Darwin Off original broker did not join descriptor retirement", err)
			}
			if !policy.offDescriptorsRetired() || policy.pf.allAbsent(closeCtx) != nil {
				t.Fatal("Darwin Off joined broker retained a kernel descriptor or scoped guard")
			}
			desktopDarwinOffHostExchange(t, network, remote)
		})
	}
}

func TestDesktopDarwinGuardianKernelOffJoinedGuardianRetainsAliasGuard(t *testing.T) {
	for _, loss := range []string{"kill", "channel-loss"} {
		t.Run(loss, func(t *testing.T) { desktopDarwinOffRetainedAliasGuard(t, loss) })
	}
}

func desktopDarwinOffRetainedAliasGuard(t *testing.T, loss string) {
	remote := desktopDarwinKernelPeer(t, "udp4")
	policy := desktopDarwinOffKernelPolicy(t, "udp4", remote)
	ctx, cancel := context.WithTimeout(context.Background(), desktopSocketControlWait)
	binding, err := policy.Select(ctx, policy.capture, "udp", remote)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	creation := DesktopSocketCreation{Capture: policy.capture, Binding: binding, Network: "udp", SocketID: strings.Repeat("1", 32)}
	created, err := policy.CreateSocket(ctx, creation)
	cancel()
	if created.File != nil {
		defer created.File.Close()
	}
	if err != nil || created.File == nil || created.prebound == nil {
		t.Fatal("Darwin Off did not return its actual bound creator socket", err)
	}
	if err := created.prebound.validate(policy, creation, created.File); err != nil {
		t.Fatal("Darwin Off actual prebound capability failed its original validation", err)
	}
	if created.prebound.validate((*DesktopDarwinSocketPolicy)(nil), creation, created.File) == nil ||
		created.prebound.validate(policy, creation, nil) == nil {
		t.Fatal("Darwin Off prebound capability borrowed another source or missing descriptor")
	}
	if _, _, err := desktopSocketSourceRaw(created.File, "udp", binding.LocalAddress); err == nil {
		t.Fatal("Darwin Off prebound descriptor entered the ordinary unbound import")
	}
	foreign, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(binding.LocalAddress, 0)))
	if err != nil {
		t.Fatal(err)
	}
	foreignFile, err := foreign.File()
	_ = foreign.Close()
	if err != nil {
		t.Fatal(err)
	}
	rejected := created.prebound.validate(policy, creation, foreignFile)
	_ = foreignFile.Close()
	if rejected == nil {
		t.Fatal("Darwin Off prebound capability accepted a different native socket")
	}
	for _, fault := range []string{"capture", "owner", "network", "socket-id", "local-address"} {
		changed := creation
		switch fault {
		case "capture":
			changed.Capture.SourceSHA256 = strings.Repeat("f", 64)
		case "owner":
			changed.Binding.Owner.Generation++
		case "network":
			changed.Network = "tcp"
		case "socket-id":
			changed.SocketID = strings.Repeat("2", 32)
		case "local-address":
			changed.Binding.LocalAddress = remote.Addr()
		}
		if err := created.prebound.validate(policy, changed, created.File); err == nil {
			t.Fatal("Darwin Off prebound capability accepted another captured authority", fault)
		}
	}
	packet, err := net.FilePacketConn(created.File)
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	if err := created.File.Close(); err != nil {
		t.Fatal(err)
	}
	if loss == "kill" {
		if err := policy.command.Process.Kill(); err != nil {
			t.Fatal(err)
		}
	} else if err := policy.channel.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-policy.joined:
	case <-time.After(3 * time.Second):
		t.Fatal("original Darwin Off guardian did not join")
	}
	closeCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	if err := policy.Close(closeCtx); err == nil {
		t.Fatal("Darwin Off guardian join fabricated engine alias retirement")
	}
	if err := policy.ReleaseSocket(closeCtx, creation); err == nil {
		t.Fatal("Darwin Off source released a still-held original engine alias")
	}
	if actual, err := desktopDarwinPFRead(closeCtx, policy.pf.Slot); err != nil || actual != policy.pf.Pointer {
		t.Fatal("Darwin Off guardian loss removed its retained creator UID guard", actual, err)
	}
	if err := packet.SetDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := packet.WriteTo([]byte("ungranted original alias"), net.UDPAddrFromAddrPort(remote)); err != nil {
		t.Fatal(err)
	}
	var body [64]byte
	if _, _, err := packet.ReadFrom(body[:]); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("Darwin Off retained isolated socket escaped after guardian join", err)
	}
	desktopDarwinOffHostExchange(t, "udp4", remote)
	if err := packet.Close(); err != nil {
		t.Fatal(err)
	}
	retire, stopRetire := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopRetire()
	if err := policy.ReleaseSocket(retire, creation); err != nil {
		t.Fatal("Darwin Off closed original alias did not permit exact source retirement", err)
	}
	if err := policy.Close(retire); err != nil || !policy.offDescriptorsRetired() {
		t.Fatal("Darwin Off joined original owner did not retire its retained guard", err)
	}
}

func TestDesktopDarwinGuardianKernelOffStateCollisionPreservesHost(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			remote := desktopDarwinKernelPeer(t, network)
			local, family := desktopDarwinTestFixture.Addresses[0], "inet"
			if network == "udp6" {
				local, family = desktopDarwinTestFixture.Addresses[2], "inet6"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			rules := fmt.Sprintf("pass out quick on lo0 %s proto udp from %s to %s port %d keep state (floating)\n", family, local, remote.Addr(), remote.Port())
			if err := desktopDarwinPFLoad(ctx, desktopDarwinPFNamespace, rules); err != nil {
				t.Fatal(err)
			}
			openHost := func() *net.UDPConn {
				t.Helper()
				connection, err := net.DialUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(local, 0)), net.UDPAddrFromAddrPort(remote))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { connection.Close() })
				desktopDarwinExchange(t, connection)
				return connection
			}
			former, unrelated := openHost(), openHost()
			collision := former.LocalAddr().(*net.UDPAddr).AddrPort()
			unrelatedLocal := unrelated.LocalAddr().(*net.UDPAddr).AddrPort()
			if err := former.Close(); err != nil {
				t.Fatal(err)
			}
			policy := desktopDarwinOffKernelPolicy(t, network, remote)
			states := func() []byte {
				t.Helper()
				ctx, stop := context.WithTimeout(context.Background(), desktopSocketControlWait)
				defer stop()
				raw, err := desktopDarwinCommand(ctx, "/sbin/pfctl", nil, "-s", "states")
				if err != nil {
					t.Fatal(err)
				}
				return raw
			}
			if desktopPFIsolatedStatesAbsent(states(), "udp", unrelatedLocal) == nil {
				t.Fatal("Darwin Off preparation removed unrelated original host state")
			}
			if desktopPFIsolatedStatesAbsent(states(), "udp", collision) == nil {
				t.Fatal("Darwin Off collision fixture lost its actual earlier floating state")
			}
			desktopDarwinExchange(t, unrelated)
			// Use the shipping isolated-UID creator and actual authenticated FD
			// transfer. This fixture owns its guardian-side copy; no engine sees
			// the unbound file. Only the bind's port choice is controlled below.
			options := policy.options
			options.HostProtectionOff = false
			pf := *policy.pf
			pf.permits = make(map[string]desktopDarwinPFPermit)
			pf.scopedSockets = make(map[string]desktopDarwinPFLocalSocket)
			guardian := &desktopDarwinGuardian{capture: policy.capture, options: options, owner: policy.owner,
				uid: policy.uid, account: policy.account, pf: &pf, sockets: make(map[string]*desktopDarwinOwnedSocket)}
			binding, err := policy.options.binding(policy.owner, remote)
			if err != nil {
				t.Fatal(err)
			}
			creation := DesktopSocketCreation{Capture: policy.capture, Binding: binding, Network: "udp", SocketID: strings.Repeat("3", 32)}
			createCtx, stopCreate := context.WithTimeout(context.Background(), desktopSocketControlWait)
			if err := pf.verify(createCtx, true); err != nil {
				stopCreate()
				t.Fatal(err)
			}
			file, err := guardian.create(createCtx, creation)
			stopCreate()
			if err != nil {
				t.Fatal("actual isolated creator did not join collision fixture", err)
			}
			defer file.Close()
			guardian.options.HostProtectionOff = true
			identity, err := desktopDarwinSocketIdentity(file)
			if err != nil || identity.uid != policy.uid {
				t.Fatal("collision fixture lost isolated kernel creator", err)
			}
			bound := false
			bind := func(fd int, address syscall.Sockaddr) error {
				if fd != int(file.Fd()) {
					return errors.New("collision fixture changed original native descriptor")
				}
				switch original := address.(type) {
				case *syscall.SockaddrInet4:
					if !local.Is4() || original.Port != 0 || original.Addr != local.As4() {
						return errors.New("collision fixture changed ephemeral address")
					}
					copy := *original
					copy.Port = int(collision.Port())
					address = &copy
				case *syscall.SockaddrInet6:
					if !local.Is6() || original.Port != 0 || original.ZoneId != 0 || original.Addr != local.As16() {
						return errors.New("collision fixture changed ephemeral address")
					}
					copy := *original
					copy.Port = int(collision.Port())
					address = &copy
				default:
					return errors.New("collision fixture changed native address family")
				}
				err := syscall.Bind(fd, address)
				bound = err == nil
				return err
			}
			inspect, stopInspect := context.WithTimeout(context.Background(), desktopSocketControlWait)
			err = guardian.prepareOffSocketWithBind(inspect, creation, file, identity, bind)
			stopInspect()
			if !bound || err == nil || !strings.Contains(err.Error(), "earlier state matching the original isolated socket") {
				t.Fatal("Darwin Off prebound source admitted actual old floating state", bound, err)
			}
			if len(pf.permits) != 0 || guardian.sockets[creation.SocketID] == nil || guardian.sockets[creation.SocketID].bound {
				t.Fatal("Darwin Off collision refusal acquired a permit or completed engine bind")
			}
			readContext, stopRead := context.WithTimeout(context.Background(), desktopSocketControlWait)
			empty, readErr := desktopDarwinPFRead(readContext, pf.Anchor)
			stopRead()
			if readErr != nil || empty != "" {
				t.Fatal("Darwin Off collision refusal installed native permission", empty, readErr)
			}
			if actual, err := desktopSocketLocal(int(file.Fd())); err != nil || actual != collision {
				t.Fatal("Darwin Off collision check did not hold its actual original tuple", actual, err)
			}
			if desktopPFIsolatedStatesAbsent(states(), "udp", unrelatedLocal) == nil {
				t.Fatal("Darwin Off collision refusal removed unrelated original host state")
			}
			desktopDarwinExchange(t, unrelated)
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			retire, stopRetire := context.WithTimeout(context.Background(), 5*time.Second)
			err = policy.Close(retire)
			stopRetire()
			if err != nil {
				t.Fatal("Darwin Off collision fixture did not retire its original source", err)
			}
			if desktopPFIsolatedStatesAbsent(states(), "udp", unrelatedLocal) == nil {
				t.Fatal("Darwin Off source teardown removed unrelated original host state")
			}
			desktopDarwinExchange(t, unrelated)
		})
	}
}
