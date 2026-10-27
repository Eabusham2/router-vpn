package multihoprelay

// TorIPCRequest/Response cross only the inherited pipes of one native child.
// A status file, HTTP response or unrelated process cannot satisfy this channel.
// The nonce is fresh for every operation, including clean shutdown.
type TorIPCRequest struct {
	Schema    int    `json:"schema"`
	Operation string `json:"operation"`
	Nonce     string `json:"nonce"`
}
type TorIPCResponse struct {
	Schema    int        `json:"schema"`
	Operation string     `json:"operation"`
	Nonce     string     `json:"nonce"`
	Receipt   TorReceipt `json:"receipt,omitempty"`
	OK        bool       `json:"ok"`
}

func (q TorIPCRequest) Valid() bool {
	return q.Schema == 1 && proofID.MatchString(q.Nonce) && (q.Operation == "snapshot" || q.Operation == "bootstrap" || q.Operation == "stop")
}
