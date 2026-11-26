package multihoprelay

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"
)

// The worker authenticates its complete measured receipt before omitting
// repeated public identities from the wire. The recipient reconstructs only
// identities from its own frozen source. Every response retains its exact
// binary64 value in position order, including sub-microsecond observations.
type nodeChainPublicReceipt struct {
	Header       NodeChainReceipt `json:"header"`
	Measurements string           `json:"measurements"`
	MAC          string           `json:"receipt_mac"`
}

func nodeChainReceiptMAC(q NodeChainRequest, receipt NodeChainReceipt) ([]byte, error) {
	family, keyHex := q.registeredBinding()
	if family == "" || !proofID.MatchString(string(keyHex)) {
		return nil, nodeChainCaptureError
	}
	key, err := hex.DecodeString(string(keyHex))
	if err != nil {
		return nil, err
	}
	defer clear(key)
	raw, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("routervpn-" + family + "-expanded-receipt-v1\x00"))
	mac.Write(raw)
	return mac.Sum(nil), nil
}

func publicReceiptWire(r NodeChainReceipt, q NodeChainRequest) (nodeChainPublicReceipt, error) {
	if !q.HasRegisteredFronts() || q.Schema == 6 && r.ExitIP != "" || r.Phase != NodeChainPending && r.Phase != NodeChainReady ||
		r.Phase == NodeChainReady && len(r.Prefixes) != len(q.Users) || r.Phase == NodeChainPending && len(r.Prefixes) != 0 {
		return nodeChainPublicReceipt{}, nodeChainCaptureError
	}
	measurements := make([]byte, 8*len(r.Prefixes))
	for i, row := range r.Prefixes {
		if row.Position != i+1 || !row.Proven || math.IsNaN(row.ResponseMS) || row.ResponseMS <= 0 || row.ResponseMS > 120000 {
			return nodeChainPublicReceipt{}, nodeChainCaptureError
		}
		binary.BigEndian.PutUint64(measurements[8*i:], math.Float64bits(row.ResponseMS))
	}
	mac, err := nodeChainReceiptMAC(q, r)
	if err != nil {
		return nodeChainPublicReceipt{}, err
	}
	r.Prefixes = nil
	return nodeChainPublicReceipt{r, base64.RawURLEncoding.EncodeToString(measurements), hex.EncodeToString(mac)}, nil
}

func (w nodeChainPublicReceipt) restore(c NodeChainCapture) (NodeChainReceipt, error) {
	r := w.Header
	if !c.Request.HasRegisteredFronts() || c.Source.Schema == 6 && r.ExitIP != "" || c.Validate() != nil || len(r.Prefixes) != 0 || !proofID.MatchString(w.MAC) ||
		(r.Phase != NodeChainPending && r.Phase != NodeChainReady) {
		return NodeChainReceipt{}, nodeChainCaptureError
	}
	count := 0
	if r.Phase == NodeChainReady {
		count = len(c.Source.Members)
	}
	if len(w.Measurements) != base64.RawURLEncoding.EncodedLen(8*count) {
		return NodeChainReceipt{}, nodeChainCaptureError
	}
	measurements, err := base64.RawURLEncoding.Strict().DecodeString(w.Measurements)
	if err != nil || len(measurements) != 8*count {
		return NodeChainReceipt{}, nodeChainCaptureError
	}
	for i := 0; i < count; i++ {
		m := c.Source.Members[i]
		ms := math.Float64frombits(binary.BigEndian.Uint64(measurements[8*i:]))
		if math.IsNaN(ms) || ms <= 0 || ms > 120000 {
			return NodeChainReceipt{}, nodeChainCaptureError
		}
		r.Prefixes = append(r.Prefixes, NodeChainPrefixReceipt{Position: m.Position, ProfileID: m.ProfileID, NodeID: m.NodeID, Mode: m.Mode, Proven: true, ResponseMS: ms, NodeKind: m.NodeKind, ProofKind: m.ProofKind, SourceSHA256: m.SourceSHA256})
	}
	received, err := hex.DecodeString(w.MAC)
	expected, macErr := nodeChainReceiptMAC(c.Request, r)
	if err != nil || macErr != nil || !hmac.Equal(received, expected) {
		return NodeChainReceipt{}, nodeChainCaptureError
	}
	return r, nil
}

type nodeChainPublicStatus struct {
	Protocol    string                 `json:"protocol"`
	LeaseSHA256 string                 `json:"lease_sha256"`
	Phase       NodeChainPhase         `json:"phase"`
	Receipt     nodeChainPublicReceipt `json:"receipt"`
}

func marshalPublicNodeChainStatus(s NodeChainLeaseStatus) ([]byte, error) {
	if s.Lease.Phase != s.Receipt.Phase {
		return nil, nodeChainCaptureError
	}
	receipt, err := publicReceiptWire(s.Receipt, s.Lease.Request)
	if err != nil {
		return nil, err
	}
	digest, err := nodeChainDigest("routervpn-"+s.Lease.Request.registeredProtocol("status-lease"), s.Lease)
	if err != nil {
		return nil, err
	}
	return boundedNodeChainFrame(nodeChainPublicStatus{s.Lease.Request.registeredProtocol("status"), digest, s.Lease.Phase, receipt}, MaxControlResponseBytes)
}

func DecodePublicNodeChainStatus(raw []byte, previous NodeChainLease, c NodeChainCapture) (NodeChainLeaseStatus, error) {
	if c.Source.Schema != 8 {
		return NodeChainLeaseStatus{}, nodeChainCaptureError
	}
	return DecodeRegisteredNodeChainStatus(raw, previous, c)
}

func DecodeRegisteredNodeChainStatus(raw []byte, previous NodeChainLease, c NodeChainCapture) (NodeChainLeaseStatus, error) {
	var w nodeChainPublicStatus
	if decodeNodeChainJSON(raw, &w, MaxControlResponseBytes) != nil || !c.Request.HasRegisteredFronts() || w.Protocol != c.Request.registeredProtocol("status") || !sameNodeChainRequest(previous.Request, c.Request) ||
		w.Phase != w.Receipt.Header.Phase {
		return NodeChainLeaseStatus{}, nodeChainCaptureError
	}
	previous.Phase = w.Phase
	digest, err := nodeChainDigest("routervpn-"+previous.Request.registeredProtocol("status-lease"), previous)
	if err != nil || w.LeaseSHA256 != digest {
		return NodeChainLeaseStatus{}, nodeChainCaptureError
	}
	r, err := w.Receipt.restore(c)
	if err != nil {
		return NodeChainLeaseStatus{}, err
	}
	return NodeChainLeaseStatus{previous, r}, nil
}

type nodeChainPublicIPCResponse struct {
	Schema         int                     `json:"schema"`
	Operation      string                  `json:"operation"`
	Nonce          string                  `json:"nonce"`
	CaptureSHA256  string                  `json:"capture_sha256"`
	OK             bool                    `json:"ok"`
	PublicReceipt  *nodeChainPublicReceipt `json:"public_receipt,omitempty"`
	PrivateReceipt *nodeChainPublicReceipt `json:"private_receipt,omitempty"`
}

func MarshalNodeChainWorkerResponse(r NodeChainIPCResponse, c NodeChainCapture) ([]byte, error) {
	if !r.Valid() {
		return nil, nodeChainCaptureError
	}
	if !c.Request.HasRegisteredFronts() || r.Receipt == nil {
		return boundedNodeChainFrame(r, NodeChainIPCMaximumBytes)
	}
	digest, err := c.Digest()
	if err != nil || r.CaptureSHA256 != digest || r.Receipt.CaptureSHA256 != digest || r.Nonce != r.Receipt.Nonce {
		return nil, nodeChainCaptureError
	}
	proof, err := publicReceiptWire(*r.Receipt, c.Request)
	if err != nil {
		return nil, err
	}
	w := nodeChainPublicIPCResponse{Schema: r.Schema, Operation: r.Operation, Nonce: r.Nonce, CaptureSHA256: r.CaptureSHA256, OK: r.OK}
	if c.Source.Schema == 6 {
		w.PrivateReceipt = &proof
	} else {
		w.PublicReceipt = &proof
	}
	return boundedNodeChainFrame(w, NodeChainIPCMaximumBytes)
}

func DecodeNodeChainWorkerResponse(raw []byte, c NodeChainCapture) (NodeChainIPCResponse, error) {
	if !c.Request.HasRegisteredFronts() {
		return DecodeNodeChainIPCResponse(raw)
	}
	if r, err := DecodeNodeChainIPCResponse(raw); err == nil {
		if r.Receipt != nil {
			return NodeChainIPCResponse{}, nodeChainCaptureError
		}
		return r, nil
	}
	var w nodeChainPublicIPCResponse
	if decodeNodeChainJSON(raw, &w, NodeChainIPCMaximumBytes) != nil || w.Schema != 1 || w.Operation != "snapshot" || !w.OK ||
		(w.PublicReceipt != nil) != (c.Source.Schema == 8) || (w.PrivateReceipt != nil) != (c.Source.Schema == 6) {
		return NodeChainIPCResponse{}, nodeChainCaptureError
	}
	proof := w.PublicReceipt
	if proof == nil {
		proof = w.PrivateReceipt
	}
	if proof == nil || w.Nonce != proof.Header.Nonce || w.CaptureSHA256 != proof.Header.CaptureSHA256 {
		return NodeChainIPCResponse{}, nodeChainCaptureError
	}
	digest, err := c.Digest()
	if err != nil || digest != w.CaptureSHA256 {
		return NodeChainIPCResponse{}, nodeChainCaptureError
	}
	receipt, err := proof.restore(c)
	if err != nil {
		return NodeChainIPCResponse{}, err
	}
	r := NodeChainIPCResponse{w.Schema, w.Operation, w.Nonce, w.CaptureSHA256, w.OK, &receipt}
	if !r.Valid() {
		return NodeChainIPCResponse{}, nodeChainCaptureError
	}
	return r, nil
}
