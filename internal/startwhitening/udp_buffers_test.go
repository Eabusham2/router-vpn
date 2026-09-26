package startwhitening

import (
	"errors"
	"net"
	"testing"
)

type bufferProbe struct {
	calls             []string
	sizes             []int
	writeErr, readErr error
}

func (p *bufferProbe) SetWriteBuffer(n int) error {
	p.calls = append(p.calls, "write")
	p.sizes = append(p.sizes, n)
	return p.writeErr
}
func (p *bufferProbe) SetReadBuffer(n int) error {
	p.calls = append(p.calls, "read")
	p.sizes = append(p.sizes, n)
	return p.readErr
}

type rawProbe struct {
	calls int
	err   error
}

func (p *rawProbe) Control(_ func(uintptr)) error { p.calls++; return p.err }
func (*rawProbe) Read(func(uintptr) bool) error   { return errors.New("unexpected read") }
func (*rawProbe) Write(func(uintptr) bool) error  { return errors.New("unexpected write") }

func TestOwnedUDPBuffersBoundedAndSetupFailuresReturned(t *testing.T) {
	if UDPSocketBufferBytes != 256*1024 {
		t.Fatal("unreviewed per-socket memory budget")
	}
	p := &bufferProbe{}
	if err := ConfigureUDPSocket(p); err != nil {
		t.Fatal(err)
	}
	if len(p.calls) != 2 || p.calls[0] != "write" || p.calls[1] != "read" || p.sizes[0] != UDPSocketBufferBytes || p.sizes[1] != UDPSocketBufferBytes {
		t.Fatal("incorrect socket buffer setup")
	}
	denied := errors.New("socket policy denied")
	p = &bufferProbe{writeErr: denied}
	if err := ConfigureUDPSocket(p); !errors.Is(err, denied) || len(p.calls) != 1 {
		t.Fatal("send failure ignored")
	}
	p = &bufferProbe{readErr: denied}
	if err := ConfigureUDPSocket(p); !errors.Is(err, denied) || len(p.calls) != 2 {
		t.Fatal("receive failure ignored")
	}
	if ConfigureUDPSocket(nil) == nil {
		t.Fatal("missing socket accepted")
	}
}
func TestUDPControlNeverChangesTCPAndDoesNotHideProtectionFailures(t *testing.T) {
	denied := errors.New("native descriptor unavailable")
	for _, network := range []string{"tcp", "tcp4", "tcp6", "unix", "ip4"} {
		p := &rawProbe{err: denied}
		if err := UDPControl(network, "", p); err != nil || p.calls != 0 {
			t.Fatal("non-UDP descriptor touched", network)
		}
	}
	for _, network := range []string{"udp", "udp4", "udp6"} {
		p := &rawProbe{err: denied}
		if err := UDPControl(network, "", p); !errors.Is(err, denied) || p.calls != 1 {
			t.Fatal("socket setup failure hidden", network)
		}
		if UDPControl(network, "", nil) == nil {
			t.Fatal("missing raw descriptor accepted")
		}
	}
}
func TestConfiguredUDPListenerRetainsTheSameAddress(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	address := c.LocalAddr().String()
	if err = ConfigureUDPSocket(c); err != nil {
		t.Fatal(err)
	}
	if c.LocalAddr().String() != address {
		t.Fatal("buffer configuration changed route identity")
	}
}
