package main

import (
	"bytes"
	"net"
	"router-vpn/internal/mtuprobe"
	"strings"
	"testing"
	"time"
)

func TestPrivateAgentMTUDatagramOwnership(t *testing.T) {
	s := &server{}
	s.cfg.Token = "fixture-token"
	s.cfg.NodeID = strings.Repeat("a", 64)
	request, _ := mtuprobe.Request(1472, s.cfg.Token, s.cfg.NodeID, time.Now())
	limiter := &mtuprobe.Limiter{}
	private := &net.UDPAddr{IP: net.ParseIP("10.77.0.2"), Port: 55000}
	reply, handled := s.mtuDatagram(request, private, limiter)
	if !handled || mtuprobe.ValidateReply(request, reply, s.cfg.Token, s.cfg.NodeID, time.Now()) != nil {
		t.Fatal("private packet not authenticated")
	}
	bad := append([]byte{}, request...)
	bad[36] ^= 1
	if reply, handled = s.mtuDatagram(bad, private, limiter); reply != nil || !handled {
		t.Fatal("invalid MTU packet fell through to cover response")
	}
	for _, address := range []net.Addr{&net.TCPAddr{IP: private.IP}, &net.UDPAddr{IP: net.ParseIP("192.0.2.1")}, nil} {
		if reply, handled = s.mtuDatagram(request, address, limiter); reply != nil || !handled {
			t.Fatal("unowned peer accepted")
		}
	}
	if reply, handled = s.mtuDatagram([]byte("ordinary-cover-datagram"), private, limiter); reply != nil || handled {
		t.Fatal("cover protocol changed")
	}
	s.cfg.Token = ""
	if reply, handled = s.mtuDatagram(request, private, limiter); reply != nil || !handled {
		t.Fatal("empty token permitted authenticated probe")
	}
}
func TestPrivateAgentRealDatagramBoundary(t *testing.T) {
	s := &server{}
	s.cfg.Token = "fixture-token"
	s.cfg.NodeID = strings.Repeat("a", 64)
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { s.servePrivateDatagrams(pc); close(done) }()
	defer func() {
		pc.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("private datagram handler survived closure")
		}
	}()
	c, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, size := range []int{128, 1232, 1472, 9000} {
		request, _ := mtuprobe.Request(size, s.cfg.Token, s.cfg.NodeID, time.Now())
		c.SetDeadline(time.Now().Add(time.Second))
		if n, err := c.Write(request); err != nil || n != size {
			t.Fatal(err)
		}
		reply := make([]byte, 9001)
		n, err := c.Read(reply)
		if err != nil || mtuprobe.ValidateReply(request, reply[:n], s.cfg.Token, s.cfg.NodeID, time.Now()) != nil {
			t.Fatal("actual private datagram failed", size, err)
		}
	}
	// Ordinary padding stays bounded and cannot amplify.
	c.SetDeadline(time.Now().Add(time.Second))
	c.Write(bytes.Repeat([]byte{9}, 1700))
	reply := make([]byte, 1800)
	n, err := c.Read(reply)
	if err != nil || n != 1200 {
		t.Fatal("cover cap changed", n, err)
	}
	request, _ := mtuprobe.Request(1400, "wrong-token", s.cfg.NodeID, time.Now())
	c.SetDeadline(time.Now().Add(100 * time.Millisecond))
	c.Write(request)
	if n, err := c.Read(reply); err == nil || n != 0 {
		t.Fatal("unauthenticated MTU probe got a response")
	}
}
