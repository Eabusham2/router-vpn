package mobiletor

import (
	"encoding/json"
	"errors"
	"strconv"

	"router-vpn/internal/mobilemtu"
)

// DesktopDeviceFixedMTU is a launch-only preference for the client interface.
// The raw exit and predecessor remain the source of their own saved policies.
type DesktopDeviceFixedMTU struct {
	Revision string `json:"revision"`
	MTU      int    `json:"mtu"`
}

func (m DesktopBridgeMetadata) NativeMTUPolicy() string {
	if m.DeviceFixedMTU != 0 {
		return "fixed"
	}
	return m.MTUPolicy
}

// WithDeviceFixedMTU recaptures the original frozen inputs through the same
// compiler that the independent child uses before opening the interface.
func (i *DesktopBridgeInputs) WithDeviceFixedMTU(revision string, mtu int) (*DesktopBridgeInputs, error) {
	if i == nil || i.policy == nil || i.capture.DeviceFixedMTU != nil {
		return nil, errors.New("desktop Tor device MTU requires the original launch capture")
	}
	capture := i.Capture()
	capture.DeviceFixedMTU = &DesktopDeviceFixedMTU{Revision: revision, MTU: mtu}
	encoded, err := json.Marshal(capture)
	if err != nil {
		return nil, err
	}
	return DecodeDesktopBridgeCapture(i.policy.Profile(), string(encoded), i.dir)
}

func (fixed *DesktopDeviceFixedMTU) apply(tun, profile map[string]any, predecessor *DesktopPredecessor) error {
	if !desktopHex(fixed.Revision, 16) || fixed.MTU < mobilemtu.MinMTU || fixed.MTU > mobilemtu.MaxMTU {
		return errors.New("desktop Tor device MTU requires a valid revision and 1280..9000 bytes")
	}
	if profile["jumbo_tun"] == true && fixed.MTU != 9000 {
		return errors.New("desktop Tor device MTU conflicts with the selected Jumbo interface")
	}
	if predecessor != nil {
		entry := predecessor.entryProof().capturedMTU()
		if entry.jumbo && fixed.MTU != 9000 || entry.fixed != 0 && fixed.MTU != entry.fixed {
			return errors.New("desktop Tor device MTU conflicts with the captured entry interface")
		}
		// Check independent packet envelopes on the original predecessor graph.
		// A matching fixed/Jumbo size already passed its own native compiler.
		if entry.fixed != fixed.MTU && !entry.jumbo {
			_, size, err := MTUInterface(predecessor.Config())
			if err != nil {
				return err
			}
			plan, err := mobilemtu.NewDeviceFixedPlan(predecessor.Config(), size)
			if err != nil {
				return err
			}
			if _, err = plan.Config(fixed.MTU); err != nil {
				return err
			}
		}
	}
	tun["mtu"] = fixed.MTU
	return nil
}

func (fixed *DesktopDeviceFixedMTU) sourceDigest(original string) string {
	if fixed == nil {
		return original
	}
	encoded, _ := json.Marshal([]string{"routervpn-desktop-tor-device-fixed-v1", original, fixed.Revision, strconv.Itoa(fixed.MTU)})
	return desktopDigest(encoded)
}
