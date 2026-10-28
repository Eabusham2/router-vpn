package mobiletor

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// This peer implements the wire boundary, including monotonic native expiry
// and ciphertext that can remain pending after STOP. No public network or
// fabricated native traffic is used as evidence: the C circuit tests separately
// exercise encryption and actual Tor queues. Here the real Go lease/control
// reader must own and validate those receipts under cancellation and time.
type paddingLeasePeer struct {
	mu         sync.Mutex
	control    *Control
	peer       net.Conn
	done       chan struct{}
	actions    []string
	grants     []time.Time
	high       uint64
	identity   PaddingIdentity
	rate       int
	expires    time.Time
	state      string
	channel    uint64
	initial    uint64
	advance    bool
	holdStop   bool
	pending    uint64
	delay      time.Duration
	startGate  chan struct{}
	gateAction string
	corrupt    func(string, string) string
}

func newPaddingLeasePeer(t *testing.T) *paddingLeasePeer {
	t.Helper()
	client, peer := net.Pipe()
	control, _ := NewControl(client)
	p := &paddingLeasePeer{control: control, peer: peer, done: make(chan struct{}), high: 6, advance: true, initial: 1}
	go func() {
		defer close(p.done)
		defer peer.Close()
		reader := bufio.NewReader(peer)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			fields := strings.Fields(line)
			if len(fields) == 2 && fields[0] == "SETCONF" {
				if _, err := io.WriteString(peer, "250 OK\r\n"); err != nil {
					return
				}
				continue
			}
			if len(fields) < 2 || fields[0] != "ROUTERVPN_PADDING" {
				t.Error("unexpected control family")
				return
			}
			action := fields[1]
			p.mu.Lock()
			p.actions = append(p.actions, action)
			if action == "INFO" {
				reply := paddingTestReplace(paddingTestCapability, "generation_highwater", strconv.FormatUint(p.high, 10))
				p.mu.Unlock()
				if _, err := io.WriteString(peer, paddingTestReply(reply)); err != nil {
					return
				}
				continue
			}
			if len(fields) < 5 {
				p.mu.Unlock()
				t.Error("missing captured control identity")
				return
			}
			generation, err := strconv.ParseUint(fields[4], 10, 64)
			if err != nil {
				p.mu.Unlock()
				t.Error("invalid generation on wire")
				return
			}
			identity := PaddingIdentity{SessionSHA256: fields[2], SourceSHA256: fields[3], Generation: generation}
			if action == "START" {
				if len(fields) != 9 || generation != p.high+1 || fields[7] != strings.Repeat("c", 32) || fields[8] != strings.Repeat("d", 64) {
					p.mu.Unlock()
					t.Error("start changed its captured policy or isolation")
					return
				}
				p.identity = identity
				p.high = generation
				p.rate, _ = strconv.Atoi(fields[5])
				p.state = "running"
				p.channel = p.initial
				ttl, _ := strconv.ParseInt(fields[6], 10, 64)
				p.expires = time.Now().Add(time.Duration(ttl) * time.Millisecond)
				p.grants = append(p.grants, p.expires)
			} else if identity != p.identity {
				p.mu.Unlock()
				t.Error("operation changed native generation owner")
				return
			} else if action == "RENEW" {
				ttl, _ := strconv.ParseInt(fields[5], 10, 64)
				p.expires = time.Now().Add(time.Duration(ttl) * time.Millisecond)
				p.grants = append(p.grants, p.expires)
			} else if action == "STOP" {
				p.state = "stopped"
				p.expires = time.Time{}
				if p.holdStop || p.pending != 0 {
					p.pending = 1
					p.state = "stopping"
				}
			} else if action != "STATUS" {
				p.mu.Unlock()
				t.Error("unknown padding action")
				return
			}
			if p.state == "stopping" && !p.holdStop {
				p.channel += p.pending
				p.pending = 0
				p.state = "stopped"
			}
			if p.state == "running" && p.advance && action != "START" {
				p.channel++
			}
			expires, reason := int64(0), "controller"
			if p.state == "running" {
				expires = int64((time.Until(p.expires) + time.Millisecond - 1) / time.Millisecond)
				reason = "active"
			}
			queued := p.channel + p.pending
			circuit := 0
			if queued > 0 {
				circuit = 17
			}
			reply := fmt.Sprintf("version=1 state=%s reason=%s session=%s source=%s generation=%d rate_kbps=%d expires_ms=%d queued_cells=%d queued_cell_bytes=%d channel_cells=%d channel_cell_bytes=%d dropped_cells=0 dropped_cell_bytes=0 pending_cells=%d last_circuit=%d", p.state, reason, p.identity.SessionSHA256, p.identity.SourceSHA256, p.identity.Generation, p.rate, expires, queued, queued*514, p.channel, p.channel*514, p.pending, circuit)
			gate, gateAction, delay, corrupt := p.startGate, p.gateAction, p.delay, p.corrupt
			p.mu.Unlock()
			if gate != nil && (action == gateAction || gateAction == "" && action == "START") {
				<-gate
			}
			if delay > 0 {
				time.Sleep(delay)
			}
			if corrupt != nil {
				reply = corrupt(action, reply)
			}
			if _, err := io.WriteString(peer, paddingTestReply(reply)); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		p.mu.Lock()
		gate := p.startGate
		p.mu.Unlock()
		if gate != nil {
			select {
			case <-gate:
			default:
				close(gate)
			}
		}
		control.Close()
		peer.Close()
		<-p.done
	})
	return p
}

func joinPaddingLeaseTest(lease *PaddingLease) {
	if lease != nil {
		lease.Cancel()
		_ = lease.Join(context.Background())
	}
}

func paddingLeaseOptions(until time.Time, retired func(error)) PaddingLeaseOptions {
	return PaddingLeaseOptions{SessionSHA256: paddingTestIdentity.SessionSHA256, SourceSHA256: paddingTestIdentity.SourceSHA256,
		Username: strings.Repeat("c", 32), Password: strings.Repeat("d", 64), RateKbps: 192, Current: func() bool { return true }, ProofValidUntil: func() time.Time { return until }, Retire: retired}
}
