package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/multihoprelay"
	"testing"
)

// Canonical saved-record model only; authenticated child capture is separately tested.
func desktopExecutionParentSavedChoice(t *testing.T, prep *mobilemultihop.NodeChainExecutionPreparation, projection *mobilemultihop.NodeChainExecutionProjection, execution string, targets ...string) mobilemultihop.NodeChainExecutionLast {
	t.Helper()
	var source mobilemultihop.NodeChainExecutionSource
	if json.Unmarshal([]byte(projection.Source()), &source) != nil {
		t.Fatal("source fixture")
	}
	policy, err := mobilemultihop.NewNodeChainExecutionPolicy(projection.Source())
	if err != nil {
		t.Fatal(err)
	}
	physical, _ := prep.DesktopPhysicalPolicy()
	_, meta, _, _ := physical.PhysicalReadValidated()
	descriptor, _ := source.Server.Digest()
	input := sha256.Sum256([]byte(prep.LocalSource()))
	target := mobilemultihop.Targets[0]
	if len(targets) == 1 {
		target = targets[0]
	} else if len(targets) > 1 {
		t.Fatal("saved choice requires one common target")
	}
	r := struct {
		Schema            int                               `json:"schema"`
		LocalSourceSHA256 string                            `json:"local_source_sha256"`
		LocalInputSHA256  string                            `json:"local_input_sha256"`
		Setting           string                            `json:"setting"`
		Execution         string                            `json:"execution"`
		Target            string                            `json:"target"`
		Descriptor        multihoprelay.NodeChainDescriptor `json:"descriptor"`
		DescriptorSHA256  string                            `json:"descriptor_sha256"`
		DNSPolicySHA256   string                            `json:"dns_policy_sha256"`
		EntryHost         string                            `json:"entry_host"`
		Peer              string                            `json:"peer"`
		FirstPort         int                               `json:"first_port"`
		LastPort          int                               `json:"last_port"`
		Port              int                               `json:"listen_port"`
		DesktopTargetOS   string                            `json:"desktop_target_os,omitempty"`
		Digest            string                            `json:"digest"`
	}{1, prep.LocalSourceSHA256(), hex.EncodeToString(input[:]), prep.Execution(), execution, target, source.Server, descriptor, source.Request.DNSPolicySHA256, policy.Front().Host, source.Request.Peer, source.FirstPort, source.LastPort, source.Request.Port, meta.TargetOS, ""}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(append([]byte("routervpn-node-chain-execution-last-v1\x00"), raw...))
	r.Digest = hex.EncodeToString(digest[:])
	raw, _ = json.Marshal(r)
	last, err := mobilemultihop.ParseNodeChainExecutionLast(string(raw), prep)
	if err != nil {
		t.Fatal(err)
	}
	return last
}
