package mobilemultihop

import (
	"context"
	"errors"
	"router-vpn/internal/nativeopenvpn"
	"time"
)

// NodeChainOpenVPNEngine reads the original connected native endpoint, never a
// configured MTU or a replacement client's most recent successful handshake.
type NodeChainOpenVPNEngine interface {
	OpenVPNMiddleStateContext(context.Context, string) (nativeopenvpn.PacketObservation, error)
}

// ConfiguredMTU is an immutable ceiling demanded by the compiled endpoint.
// It is never evidence that a native connection exists or has this capacity.
type NodeChainOpenVPNCapture struct {
	Tag           string
	SourceSHA256  string
	Remote        nativeopenvpn.Remote
	ConfiguredMTU int
}

func (c *NodeChain) OpenVPNMiddleCapture() (NodeChainOpenVPNCapture, error) {
	empty := NodeChainOpenVPNCapture{}
	if c.validateCapture() != nil {
		return empty, nodeChainError
	}
	if c.openVPNMiddle == nil {
		return empty, nil
	}
	var graph map[string]any
	if exactJSON([]byte(c.config), &graph, NodeChainInputLimit) != nil {
		return empty, nodeChainError
	}
	ends, _ := graph["endpoints"].([]any)
	for _, raw := range ends {
		endpoint, ok := raw.(map[string]any)
		if !ok || endpoint["tag"] != c.proofs[c.importedMiddlePosition()].Tag {
			continue
		}
		remotes, err := nativeopenvpn.Remotes(endpoint)
		mtu, ok := endpoint["mtu"].(float64)
		if err != nil || len(remotes) != 1 || !ok || mtu < 1280 || mtu > 65535 || mtu != float64(int(mtu)) {
			return empty, nodeChainError
		}
		return NodeChainOpenVPNCapture{c.proofs[c.importedMiddlePosition()].Tag, c.openVPNMiddle.source, remotes[0], int(mtu)}, nil
	}
	return empty, nodeChainError
}

func (c *NodeChain) observeOpenVPNMiddleContext(ctx context.Context, engine NodeChainEngine, initial bool) error {
	if c.openVPNMiddle == nil {
		return nil
	}
	capture, err := c.OpenVPNMiddleCapture()
	if err != nil {
		return err
	}
	native, ok := engine.(NodeChainOpenVPNEngine)
	if !ok {
		return errors.New("ordered OpenVPN middle has no original native observer")
	}
	for {
		state, err := native.OpenVPNMiddleStateContext(ctx, capture.Tag)
		if err != nil && initial && errors.Is(err, nativeopenvpn.ErrRemotePending) {
			timer := time.NewTimer(40 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
				continue
			}
		}
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if state.Validate() != nil || state.Remote.Remote != capture.Remote || state.MTU < uint32(capture.ConfiguredMTU) {
			return errors.New("ordered OpenVPN middle lost its original remote or native packet capacity")
		}
		if err := externalObservationLock(ctx, &c.runtime.mu); err != nil {
			return err
		}
		original := c.runtime.openVPN
		if original == nil && initial && !c.runtime.closed {
			copy := state
			c.runtime.openVPN = &copy
			original = &copy
		}
		valid := original != nil && *original == state && !c.runtime.closed
		c.runtime.mu.Unlock()
		if !valid {
			return errors.New("ordered OpenVPN middle connected generation or packet capacity changed")
		}
		return nil
	}
}
