package mobilemultihop

import (
	"router-vpn/internal/multihoprelay"
	"strings"
	"testing"
	"time"
)

func serverCandidateFixture(t *testing.T, c multihoprelay.NodeChainCapture, address string) multihoprelay.NodeChainCandidateCapture {
	t.Helper()
	digest, err := c.Digest()
	if err != nil {
		t.Fatal(err)
	}
	q := multihoprelay.NodeChainCandidateRequest{Schema: 1, Lease: c.Request.Clone(), OwnerID: c.OwnerID, CaptureSHA256: digest, Operation: strings.Repeat("a", 64), ExecutionSHA256: strings.Repeat("b", 64), Trial: strings.Repeat("c", 32), SelectionEpoch: 1, InventorySHA256: strings.Repeat("d", 64), Position: 1, CandidateID: "candidate", CandidateSourceSHA256: strings.Repeat("e", 64), Address: address, DeadlineAt: time.Now().Add(time.Minute).UnixMilli(), Password: strings.Repeat("9", 64)}
	capture, err := multihoprelay.NewNodeChainCandidateCapture(c, q, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return capture
}
func TestNodeChainServerCandidateOriginalPacketTarget(t *testing.T) {
	p, lease := nodeChainServerFixture(t, 4, "")
	c := serverCandidateFixture(t, lease, "192.168.1.9:443")
	target, err := p.CandidateTarget(c)
	if err != nil {
		t.Fatal("captured LAN access was silently banned", err)
	}
	tag, address, err := target.Read(p, c)
	if err != nil || tag != p.proofs[0].Tag || address != c.Request.Address {
		t.Fatal("original packet target lost", err)
	}
	copied := *target
	if _, _, err = copied.Read(p, c); err == nil {
		t.Fatal("copied target admitted")
	}
	foreign, err := NewNodeChainServerPolicy(p.Source())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = target.Read(foreign, c); err == nil {
		t.Fatal("equal-value policy replaced original")
	}
	changed := c.Clone()
	changed.Request.Address = "192.168.1.10:443"
	if _, _, err = target.Read(p, changed); err == nil {
		t.Fatal("target address substituted")
	}
	routes, err := p.FrontRoutes(lease)
	if err != nil {
		t.Fatal(err)
	}
	if routes[0].AllowsDestination("tcp", c.Request.Address) {
		t.Fatal("existing proof-only route was broadened")
	}
}
func TestNodeChainServerCandidateRetainsLANAndIPv6Policy(t *testing.T) {
	source := nodeChainServerSourceFixture(t, 4, "")
	node, err := ParseNodeLaunchInput(source.Nodes[0])
	if err != nil {
		t.Fatal(err)
	}
	profile := predecessorCopy(node.profile)
	profile["ipv6_mode"], profile["home_lan_access"], profile["home_lan_cidrs"] = "off", false, []string{"10.12.0.0/16"}
	node, err = NewNodeProfile(node.mode, node.inputs.Files, startJSON(t, profile), node.inputs.Start, node.inputs.DNSBootstrap)
	if err != nil {
		t.Fatal(err)
	}
	source.Nodes[0], err = node.LaunchInput()
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewNodeChainServerPolicy(startJSON(t, source))
	if err != nil {
		t.Fatal(err)
	}
	lease := nodeChainServerCaptureFixture(t, p)
	for _, address := range []string{"10.12.1.1:443", "[2001:db8::1]:443"} {
		c := serverCandidateFixture(t, lease, address)
		if _, err = p.CandidateTarget(c); err == nil {
			t.Fatal("candidate bypassed original address policy", address)
		}
	}
	c := serverCandidateFixture(t, lease, "192.168.1.9:443")
	if _, err = p.CandidateTarget(c); err != nil {
		t.Fatal("unblocked captured LAN choice rejected", err)
	}
}
