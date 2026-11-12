package mobilemultihop

import (
	"reflect"
	"time"

	"router-vpn/internal/multihoprelay"
)

// NodeChainExecutionDiscovery is read only through the original authenticated
// entry route. A JSON value by itself is not authentication or path proof.
type NodeChainExecutionDiscovery struct {
	NodeID    string                                `json:"node_id"`
	Challenge multihoprelay.ExternalPacketChallenge `json:"challenge"`
	Sources   []multihoprelay.NodeChainDescriptor   `json:"sources"`
	FirstPort int                                   `json:"first_port"`
	LastPort  int                                   `json:"last_port"`
}

// NewAttempt captures one fresh acquisition without rebuilding the native
// graph or changing its selected front. Runtime must first prove retirement of
// every prior attempt, then retain this exact request before a PUT can start
// remote work. Renewal/status/delete always use that retained request. A fresh
// challenge never reopens or extends a tombstoned request, nor reruns Compare
// when restoring an already proved execution choice.
func (p *NodeChainExecutionPolicy) NewAttempt(discoveryJSON string) (multihoprelay.NodeChainRequest, error) {
	return p.newAttemptAt(discoveryJSON, time.Now())
}

func (p *NodeChainExecutionPolicy) newAttemptAt(discoveryJSON string, now time.Time) (multihoprelay.NodeChainRequest, error) {
	var discovery NodeChainExecutionDiscovery
	if p.validateCapture() != nil || now.IsZero() || exactJSON([]byte(discoveryJSON), &discovery, 512<<10) != nil ||
		discovery.NodeID != p.source.Server.EntryNodeID || discovery.Challenge.Validate() != nil || discovery.Challenge.Peer != p.source.Request.Peer ||
		discovery.Challenge.ExpiresAt <= now.Unix() || discovery.Challenge.ExpiresAt > now.Add(time.Minute).Unix() ||
		discovery.FirstPort != p.source.FirstPort || discovery.LastPort != p.source.LastPort || len(discovery.Sources) < 1 || len(discovery.Sources) > multihoprelay.MaxPairedExits {
		return multihoprelay.NodeChainRequest{}, nodeChainExecutionError
	}
	seen, matched := map[string]bool{}, false
	for _, source := range discovery.Sources {
		if source.Validate() != nil || source.EntryNodeID != discovery.NodeID || seen[source.SourceSHA256] {
			return multihoprelay.NodeChainRequest{}, nodeChainExecutionError
		}
		seen[source.SourceSHA256] = true
		if reflect.DeepEqual(source, p.source.Server) {
			matched = true
		}
	}
	if !matched {
		return multihoprelay.NodeChainRequest{}, nodeChainExecutionError
	}
	request := p.source.Request.Clone()
	var err error
	for i := 0; i < 3; i++ {
		request.SessionID, err = randomHex(16)
		if err != nil {
			return multihoprelay.NodeChainRequest{}, nodeChainExecutionError
		}
		if request.SessionID != p.source.Request.SessionID {
			break
		}
	}
	if request.SessionID == p.source.Request.SessionID {
		return multihoprelay.NodeChainRequest{}, nodeChainExecutionError
	}
	request.Epoch, request.AcquireExpiresAt = discovery.Challenge.Epoch, discovery.Challenge.ExpiresAt
	if request.Validate(p.source.Server) != nil {
		return multihoprelay.NodeChainRequest{}, nodeChainExecutionError
	}
	return request, nil
}
