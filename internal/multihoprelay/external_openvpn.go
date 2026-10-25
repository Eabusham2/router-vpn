package multihoprelay

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"unicode/utf8"

	"router-vpn/internal/applexray"
	"router-vpn/internal/nativeopenvpn"
)

// ExternalOpenVPNPair contains one role's private provider profile and dedicated
// pairing key. The opposite role is represented only by a public descriptor.
// These names and public identities stay in private bundles, never discovery.
type ExternalOpenVPNPair struct {
	Owner      string                         `json:"owner"`
	PrivateKey string                         `json:"private_key"`
	Profile    nativeopenvpn.Profile          `json:"profile"`
	Local      nativeopenvpn.PublicDescriptor `json:"local"`
	Server     nativeopenvpn.PublicDescriptor `json:"server"`
}

var errExternalOpenVPN = errors.New("OpenVPN relay requires separate owned provider credentials, pairing keys and exact captured transport policy")

func (pair *ExternalOpenVPNPair) UnmarshalJSON(raw []byte) error {
	if len(raw) > 2<<20 {
		return errExternalOpenVPN
	}
	object, err := applexray.Object(raw)
	if err != nil || len(object) != 5 {
		return errExternalOpenVPN
	}
	for _, key := range []string{"owner", "private_key"} {
		if _, ok := object[key].(string); !ok {
			return errExternalOpenVPN
		}
	}
	for _, key := range []string{"profile", "local", "server"} {
		if _, ok := object[key].(map[string]any); !ok {
			return errExternalOpenVPN
		}
	}
	type plain ExternalOpenVPNPair
	var result plain
	if json.Unmarshal(raw, &result) != nil || result.Owner != "client" && result.Owner != "server" {
		return errExternalOpenVPN
	}
	*pair = ExternalOpenVPNPair(result)
	return nil
}

// ExternalIndependentMode uses short-lived peer/epoch-bound acquisition for
// protocols whose Local and Server engines have independent credential owners.
// The existing packet challenge wire format remains backward compatible.
func ExternalIndependentMode(mode string) bool { return ExternalPacketMode(mode) || mode == "openvpn" }

func externalIndependentOwner(exit Exit) string {
	if exit.External == nil {
		return ""
	}
	if ExternalPacketMode(exit.Mode) && exit.External.Packet != nil {
		return exit.External.Packet.Owner
	}
	if exit.Mode == "openvpn" && exit.External.OpenVPN != nil {
		return exit.External.OpenVPN.Owner
	}
	return ""
}

func externalOpenVPNProfile(raw any) (nativeopenvpn.Profile, error) {
	object, ok := raw.(map[string]any)
	if !ok {
		return nativeopenvpn.Profile{}, errExternalOpenVPN
	}
	for _, value := range object {
		text, ok := value.(string)
		if !ok || !utf8.ValidString(text) {
			return nativeopenvpn.Profile{}, errExternalOpenVPN
		}
	}
	encoded, err := json.Marshal(raw)
	var profile nativeopenvpn.Profile
	if err != nil || json.Unmarshal(encoded, &profile) != nil {
		return profile, errExternalOpenVPN
	}
	return profile, nil
}

func externalOpenVPNTransport(external map[string]any) (map[string]any, error) {
	if external["protocol"] != "openvpn" {
		return nil, errExternalOpenVPN
	}
	allowed := map[string]bool{"protocol": true, "openvpn": true, "openvpn_pairing": true, "openvpn_response_probes": true, "expected_public_ip": true, "response_probe": true, "start_layer": true}
	for key := range external {
		if !allowed[key] {
			return nil, errExternalOpenVPN
		}
	}
	profile, err := externalOpenVPNProfile(external["openvpn"])
	if err != nil {
		return nil, err
	}
	transport, err := nativeopenvpn.CompileProfile(profile, "exit", "")
	if err != nil {
		return nil, err
	}
	if raw, present := external["openvpn_response_probes"]; present {
		_, legacy := external["response_probe"]
		_, layered := external["start_layer"]
		if legacy || layered {
			return nil, errExternalOpenVPN
		}
		encoded, err := json.Marshal(raw)
		var probes nativeopenvpn.ResponseProbes
		if err != nil || json.Unmarshal(encoded, &probes) != nil || probes.Validate(transport) != nil {
			return nil, errExternalOpenVPN
		}
	}
	return transport, nil
}

func externalOpenVPNSelection(external map[string]any) (*ExternalOpenVPNPair, error) {
	profile, err := externalOpenVPNProfile(external["openvpn"])
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(external["openvpn_pairing"])
	var pairing nativeopenvpn.Pairing
	if err != nil || json.Unmarshal(raw, &pairing) != nil {
		return nil, errExternalOpenVPN
	}
	local, err := nativeopenvpn.ValidatePairing(profile, pairing)
	if err != nil {
		return nil, errExternalOpenVPN
	}
	return &ExternalOpenVPNPair{Owner: "client", PrivateKey: pairing.PrivateKey, Profile: profile, Local: local, Server: pairing.Server}, nil
}

// ValidateExternalOpenVPNPairing is also used for Local captures. An optional
// private pairing must be complete and belong to this exact original profile
// even when this connection does not acquire a relay.
func ValidateExternalOpenVPNPairing(protocol string, external map[string]any) error {
	if _, exists := external["openvpn_pairing"]; !exists {
		return nil
	}
	if protocol != "openvpn" {
		return errExternalOpenVPN
	}
	_, err := externalOpenVPNSelection(external)
	return err
}

func ValidateExternalOpenVPNResponseProbes(protocol string, external map[string]any) error {
	if _, exists := external["openvpn_response_probes"]; !exists {
		return nil
	}
	if protocol != "openvpn" {
		return errExternalOpenVPN
	}
	_, err := externalOpenVPNTransport(external)
	return err
}

func validateExternalOpenVPN(exit Exit) (map[string]any, error) {
	if exit.Mode != "openvpn" || exit.External == nil || exit.External.Packet != nil || exit.External.OpenVPN == nil || exit.NodeID != "" || !externalPublicIP(exit.External.ExpectedPublicIP) {
		return nil, errExternalOpenVPN
	}
	pair := exit.External.OpenVPN
	if pair.Owner != "client" && pair.Owner != "server" || nativeopenvpn.ValidatePublicPair(pair.Local, pair.Server) != nil {
		return nil, errExternalOpenVPN
	}
	transport, err := nativeopenvpn.CompileProfile(pair.Profile, "exit", "")
	if err != nil || !reflect.DeepEqual(transport, exit.Transport) {
		return nil, errExternalOpenVPN
	}
	public, err := nativeopenvpn.DescribePeer(pair.Profile, pair.PrivateKey)
	owned, other := pair.Local, pair.Server
	if pair.Owner == "server" {
		owned, other = other, owned
	}
	if err != nil || !reflect.DeepEqual(public, owned) {
		return nil, errExternalOpenVPN
	}
	shared, err := nativeopenvpn.PairingAgreement(pair.PrivateKey, other.PairingPublicKey)
	if err != nil {
		return nil, errExternalOpenVPN
	}
	clear(shared)
	if exit.External.OpenVPNResponseProbes != nil {
		if exit.External.ResponseProbe != (ResponseProbe{}) || exit.StartLayer != nil || exit.External.OpenVPNResponseProbes.Validate(transport) != nil {
			return nil, errExternalOpenVPN
		}
	} else {
		host, err := nativeopenvpn.SameRemoteHost(transport)
		if err != nil || exit.External.ResponseProbe.Validate(host) != nil {
			return nil, errExternalOpenVPN
		}
	}
	if exit.StartLayer != nil {
		if _, _, err := WrapStartLayer(transport, exit.Mode, exit.StartLayer, ExitStartLayerTag, ""); err != nil {
			return nil, errExternalOpenVPN
		}
	}
	return transport, nil
}

func externalOpenVPNAuthKey(exit Exit, fingerprint string) ([]byte, error) {
	pair := exit.External.OpenVPN
	other := pair.Server
	if pair.Owner == "server" {
		other = pair.Local
	}
	shared, err := nativeopenvpn.PairingAgreement(pair.PrivateKey, other.PairingPublicKey)
	if err != nil {
		return nil, errExternalOpenVPN
	}
	defer clear(shared)
	var layerSecret any
	if exit.StartLayer != nil {
		layerSecret = exit.StartLayer.Transport["password"]
	}
	version := externalOpenVPNVersion(exit)
	raw, _ := json.Marshal([]any{"routervpn-external-openvpn-salt-" + version, fingerprint, layerSecret})
	salt := sha256.Sum256(raw)
	clear(raw)
	return packetHKDF(shared, salt[:], "routervpn-external-openvpn-lease-"+version), nil
}

func externalOpenVPNVersion(exit Exit) string {
	if OpenVPNRemoteRequired(exit) {
		return "v5"
	}
	return "v4"
}

func OpenVPNRemoteRequired(exit Exit) bool {
	return exit.Mode == "openvpn" && exit.External != nil && exit.External.OpenVPNResponseProbes != nil
}

func externalOpenVPNServerProfile(source map[string]any) (nativeopenvpn.Profile, string, error) {
	if len(source) != 3 || source["protocol"] != "openvpn" {
		return nativeopenvpn.Profile{}, "", errExternalOpenVPN
	}
	private, ok := source["pairing_private_key"].(string)
	if !ok {
		return nativeopenvpn.Profile{}, "", errExternalOpenVPN
	}
	profile, err := externalOpenVPNProfile(source["openvpn"])
	return profile, private, err
}

// ExternalOpenVPNServerDescriptor is an offline export from the server owner's
// private profile. No provider key, password, control key or pairing secret is
// included in its result. It is imported only into a private client bundle.
func ExternalOpenVPNServerDescriptor(source map[string]any) (nativeopenvpn.PublicDescriptor, error) {
	profile, private, err := externalOpenVPNServerProfile(source)
	if err != nil {
		return nativeopenvpn.PublicDescriptor{}, err
	}
	return nativeopenvpn.DescribePeer(profile, private)
}

// PairExternalOpenVPN discards all Local private material after proving the
// counterpart descriptors. Only the Server-owned original inline source and
// dedicated pairing key survive in the administrator's registry entry.
func PairExternalOpenVPN(id string, external, serverSource map[string]any, layer *StartLayer) (Exit, error) {
	client, err := ExternalSelection(id, "openvpn", external, layer)
	if err != nil {
		return Exit{}, err
	}
	profile, private, err := externalOpenVPNServerProfile(serverSource)
	if err != nil {
		return Exit{}, err
	}
	transport, err := nativeopenvpn.CompileProfile(profile, "exit", "")
	if err != nil {
		return Exit{}, err
	}
	pair := client.External.OpenVPN
	client.Transport = transport
	client.External.OpenVPN = &ExternalOpenVPNPair{Owner: "server", PrivateKey: private, Profile: profile, Local: pair.Local, Server: pair.Server}
	if _, err := validateExternalOpenVPN(client); err != nil {
		return Exit{}, err
	}
	return client, nil
}

func (m *Manager) validateOpenVPNConcurrentOwnerLocked(exit Exit) error {
	if exit.Mode != "openvpn" {
		return nil
	}
	if exit.External == nil || exit.External.OpenVPN == nil || exit.External.OpenVPN.Owner != "server" {
		return ErrOwnership
	}
	identity := exit.External.OpenVPN.Server.ProviderIdentity
	for _, active := range m.leases {
		if active.ExitMode != "openvpn" {
			continue
		}
		for _, other := range m.cfg.Exits {
			if other.ID != active.ExitID || other.Mode != active.ExitMode || LayerMode(other.StartLayer) != active.ExitStartLayer {
				continue
			}
			if other.External == nil || other.External.OpenVPN == nil {
				return ErrOwnership
			}
			if nativeopenvpn.ProviderSessionsOverlap(identity, other.External.OpenVPN.Server.ProviderIdentity) {
				return errors.New("paired OpenVPN provider credentials already own another relay; provision independent client credentials")
			}
		}
	}
	return nil
}
