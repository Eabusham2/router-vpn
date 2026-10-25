package common

import (
	"errors"
	"router-vpn/internal/nativeopenvpn"
)

func validateExternalOpenVPNPairing(external *ExternalNodeConfig) error {
	if external.OpenVPNPairing == nil {
		return nil
	}
	if external.Protocol != "openvpn" || external.OpenVPN == nil || external.ServerPeer != nil {
		return errors.New("OpenVPN pairing belongs only to its captured original OpenVPN profile")
	}
	_, err := nativeopenvpn.ValidatePairing(*external.OpenVPN, *external.OpenVPNPairing)
	return err
}

func validateExternalOpenVPNResponseProbes(external *ExternalNodeConfig) error {
	if external.OpenVPNResponseProbes == nil {
		if external.OpenVPNStartLayers != nil { return errors.New("OpenVPN Start Layers require a complete captured remote response map") }
		return nil
	}
	if external.Protocol != "openvpn" || external.OpenVPN == nil || external.ResponseProbe != nil || external.StartLayer != nil {
		return errors.New("OpenVPN remote responses require a complete captured host map without a legacy response or unmapped exit layer")
	}
	endpoint, err := nativeopenvpn.CompileProfile(*external.OpenVPN, "exit", "")
	if err != nil {
		return err
	}
	return external.OpenVPNResponseProbes.Validate(endpoint)
}

func validateExternalOpenVPNStartLayers(profile *RouterProfile) error {
	external := profile.External
	if external == nil || external.Protocol != "openvpn" || external.OpenVPN == nil || external.ResponseProbe != nil || external.StartLayer != nil || external.OpenVPNResponseProbes == nil {
		return errors.New("OpenVPN Start Layers require their original OpenVPN profile and complete private response map")
	}
	endpoint, err := nativeopenvpn.CompileProfile(*external.OpenVPN, "exit", "")
	if err != nil { return err }
	if err := external.OpenVPNStartLayers.Validate(endpoint, external.OpenVPNResponseProbes, profile.StartLayer); err != nil { return err }
	if external.OpenVPNPairing != nil {
		local, err := nativeopenvpn.ValidatePairing(*external.OpenVPN, *external.OpenVPNPairing)
		if err != nil { return err }
		return external.OpenVPNStartLayers.ValidatePairingKeys(local.PairingPublicKey, external.OpenVPNPairing.Server.PairingPublicKey)
	}
	return nil
}

func externalOpenVPNProofHost(external *ExternalNodeConfig) (string, error) {
	if external == nil || external.OpenVPN == nil {
		return "", errors.New("OpenVPN response or Start Layer requires its captured inline profile")
	}
	endpoint, err := nativeopenvpn.CompileProfile(*external.OpenVPN, "exit", "")
	if err != nil {
		return "", err
	}
	return nativeopenvpn.SameRemoteHost(endpoint)
}

func externalOpenVPNFirstHost(external *ExternalNodeConfig) string {
	if external == nil || external.OpenVPN == nil {
		return ""
	}
	endpoint, err := nativeopenvpn.CompileProfile(*external.OpenVPN, "exit", "")
	if err != nil {
		return ""
	}
	if host, ok := endpoint["server"].(string); ok {
		return host
	}
	if remotes, ok := endpoint["servers"].([]any); ok && len(remotes) != 0 {
		if first, ok := remotes[0].(map[string]any); ok {
			host, _ := first["server"].(string)
			return host
		}
	}
	return ""
}
