package linuxprotection

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"router-vpn/internal/mobiletor"
)

const NodeControlSchema = 1
const NodeControlKind = "routervpn-linux-node-control-v1"
const NodeControlMessageLimit = 12000

// NodeSelection is captured independently from the sealed policy on both
// sides of the original inherited channel. Its command digest binds the
// bootstrap; its control digest additionally binds the selected protection
// and LAN policy before the parent can create a baseline.
type NodeSelection struct {
	SessionID    string `json:"session_id"`
	SourceSHA256 string `json:"source_sha256"`
	ConfigSHA256 string `json:"config_sha256"`
	Policy       string `json:"policy"`
	HomeLAN      bool   `json:"home_lan"`
}

func (s NodeSelection) Validate() error {
	if _, err := s.CaptureSHA256(); err != nil || s.Policy != "on-connect" && s.Policy != "always" {
		return errors.New("Linux Node control lost its captured command and selected protection")
	}
	return nil
}

func (s NodeSelection) CaptureSHA256() (string, error) {
	return NodeCommandCaptureSHA256(s.SessionID, s.SourceSHA256, s.ConfigSHA256)
}

func (s NodeSelection) ControlSHA256() (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	return nodeControlDigest("routervpn-linux-node-selection-v1", s, nil)
}

func (s NodeSelection) matches(c mobiletor.DesktopSocketCapture) bool {
	return s.Validate() == nil && c.SessionID == s.SessionID && c.SourceSHA256 == s.SourceSHA256 && lowerHex(c.NetworkID, 32)
}

// NodePreparedRecord compares the actual unused source and its created
// guardian with the parent's original baseline receipt. Decoding it never
// creates a process witness or authorizes adoption of a named nft table.
type NodePreparedRecord struct {
	Protection mobiletor.DesktopLinuxProtectionRecord `json:"protection"`
	Guardian   mobiletor.DesktopLinuxGuardianRecord   `json:"guardian"`
	Policy     string                                 `json:"policy"`
}

func (r NodePreparedRecord) Validate() error {
	if r.Protection.Validate() != nil || r.Protection.TableName == "" || r.Guardian.Validate() != nil ||
		uint32(r.Guardian.Guardian.ProcessID) != r.Protection.Owner.ProcessID || r.Policy != "on-connect" && r.Policy != "always" {
		return errors.New("Linux Node prepared record lost its scoped baseline or original guardian")
	}
	return nil
}

// NodeRetirementRecord reports only the source returned by this original
// engine. A partial constructor need not invent a complete native guardian;
// no returned source is distinct from proving native baseline absence. The
// parent still owes its own closed readback and actual engine join before
// durable rollback, release or Always retention can settle.
type NodeRetirementRecord struct {
	Source   *mobiletor.DesktopLinuxSourceJoinRecord `json:"source,omitempty"`
	Prepared *NodePreparedRecord                     `json:"prepared,omitempty"`
}

func (r NodeRetirementRecord) Validate() error {
	if r.Source == nil {
		if r.Prepared != nil {
			return errors.New("Linux Node retirement erased its prepared source")
		}
		return nil
	}
	if r.Source.Validate() != nil {
		return errors.New("Linux Node retirement lost its original joined source")
	}
	if r.Prepared != nil && (r.Prepared.Validate() != nil || r.Source.Original == nil ||
		r.Source.Capture != r.Prepared.Protection.Capture || *r.Source.Original != r.Prepared.Guardian) {
		return errors.New("Linux Node retirement substituted its original prepared guardian")
	}
	return nil
}

func (r NodeRetirementRecord) Clone() NodeRetirementRecord {
	if r.Source != nil {
		copy := r.Source.Clone()
		r.Source = &copy
	}
	if r.Prepared != nil {
		copy := *r.Prepared
		r.Prepared = &copy
	}
	return r
}

func nodeControlDigest(kind string, selection NodeSelection, record any) (string, error) {
	body, err := json.Marshal(struct {
		Kind      string        `json:"kind"`
		Selection NodeSelection `json:"selection"`
		Record    any           `json:"record,omitempty"`
	}{kind, selection, record})
	if err != nil || len(body) > NodeControlMessageLimit {
		return "", errors.New("Linux Node receipt exceeds its fixed encoding bound")
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}

func NodePreparedSHA256(selection NodeSelection, record NodePreparedRecord) (string, error) {
	if record.Validate() != nil || !selection.matches(record.Protection.Capture) || record.Policy != selection.Policy {
		return "", errors.New("Linux Node prepared receipt belongs to another captured selection")
	}
	return nodeControlDigest("routervpn-linux-node-prepared-v1", selection, record)
}

func NodeRetirementSHA256(selection NodeSelection, record NodeRetirementRecord) (string, error) {
	if selection.Validate() != nil || record.Validate() != nil || record.Source != nil && !selection.matches(record.Source.Capture) ||
		record.Prepared != nil && record.Prepared.Policy != selection.Policy {
		return "", errors.New("Linux Node retirement receipt belongs to another captured selection")
	}
	return nodeControlDigest("routervpn-linux-node-retired-v1", selection, record)
}

// NodeControlMessage is bounded comparison data carried only by the original
// authenticated Bootstrap. The stateful owner must also enforce direction,
// its next sequence, original native observations and captured callback phase.
// The codec alone is neither an admission nor a cleanup capability.
type NodeControlMessage struct {
	Schema          int                                       `json:"schema"`
	Kind            string                                    `json:"kind"`
	Sequence        uint32                                    `json:"sequence"`
	SelectionSHA256 string                                    `json:"selection_sha256"`
	Action          string                                    `json:"action"`
	Network         string                                    `json:"network,omitempty"`
	Created         *mobiletor.DesktopLinuxNodeCreationRecord `json:"created,omitempty"`
	Prepared        *NodePreparedRecord                       `json:"prepared,omitempty"`
	Retired         *NodeRetirementRecord                     `json:"retired,omitempty"`
	ReceiptSHA256   string                                    `json:"receipt_sha256,omitempty"`
	Refusal         string                                    `json:"refusal,omitempty"`
}

func (m NodeControlMessage) Validate() error {
	if m.Schema != NodeControlSchema || m.Kind != NodeControlKind || m.Sequence == 0 || m.Sequence > 6 || !lowerHex(m.SelectionSHA256, 64) {
		return errors.New("Linux Node message lost its bounded captured envelope")
	}
	fields := 0
	for _, present := range []bool{m.Network != "", m.Created != nil, m.Prepared != nil, m.Retired != nil, m.ReceiptSHA256 != "", m.Refusal != ""} {
		if present {
			fields++
		}
	}
	if fields != 1 {
		return errors.New("Linux Node message must carry exactly one phase payload")
	}
	valid := false
	switch m.Action {
	case "baseline":
		valid = m.Sequence == 1 && lowerHex(m.Network, 32)
	case "created":
		valid = m.Sequence == 2 && m.Created != nil && m.Created.Validate() == nil
	case "prepared":
		valid = m.Sequence == 3 && m.Prepared != nil && m.Prepared.Validate() == nil
	case "admitted":
		valid = m.Sequence == 4 && lowerHex(m.ReceiptSHA256, 64)
	case "refused":
		valid = m.Sequence == 2 && m.Refusal == "baseline" || m.Sequence == 4 && m.Refusal == "admission"
	case "retired":
		valid = m.Sequence%2 == 1 && m.Retired != nil && m.Retired.Validate() == nil
	case "closed":
		valid = m.Sequence%2 == 0 && lowerHex(m.ReceiptSHA256, 64)
	}
	if !valid {
		return errors.New("Linux Node message changed its original phase payload")
	}
	return nil
}

func (m NodeControlMessage) Clone() NodeControlMessage {
	if m.Created != nil {
		copy := *m.Created
		m.Created = &copy
	}
	if m.Prepared != nil {
		copy := *m.Prepared
		m.Prepared = &copy
	}
	if m.Retired != nil {
		copy := m.Retired.Clone()
		m.Retired = &copy
	}
	return m
}

func CanonicalNodeControlMessage(message NodeControlMessage) ([]byte, error) {
	if err := message.Validate(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(message)
	if err != nil || len(body) == 0 || len(body) > NodeControlMessageLimit {
		return nil, errors.New("Linux Node message exceeds its fixed encoding bound")
	}
	return body, nil
}

func ParseNodeControlMessage(body []byte) (NodeControlMessage, error) {
	if len(body) == 0 || len(body) > NodeControlMessageLimit {
		return NodeControlMessage{}, errors.New("Linux Node message is empty or unbounded")
	}
	var message NodeControlMessage
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&message) != nil {
		return NodeControlMessage{}, errors.New("Linux Node message has unsupported fields or types")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return NodeControlMessage{}, errors.New("Linux Node message has trailing content")
	}
	canonical, err := CanonicalNodeControlMessage(message)
	if err != nil || !bytes.Equal(canonical, body) {
		return NodeControlMessage{}, errors.New("Linux Node message is not its exact canonical encoding")
	}
	return message, nil
}
