package main

import (
	"net"
	"router-vpn/internal/mtuprobe"
	"time"
)

const maxPrivateDatagram = mtuprobe.MaxBytes

// A recognized but invalid request is consumed without replying. It must never
// fall through to the unauthenticated, smaller cover-response protocol.
func (s *server) mtuDatagram(packet []byte, address net.Addr, budget *mtuprobe.Limiter) ([]byte, bool) {
	if !mtuprobe.Recognized(packet) {
		return nil, false
	}
	peer, ok := address.(*net.UDPAddr)
	if !ok || budget == nil {
		return nil, true
	}
	now := time.Now()
	if !budget.Allow(peer.AddrPort().Addr(), now) {
		return nil, true
	}
	reply, err := mtuprobe.Reply(packet, s.cfg.Token, s.cfg.NodeID, now)
	if err != nil {
		return nil, true
	}
	return reply, true
}
