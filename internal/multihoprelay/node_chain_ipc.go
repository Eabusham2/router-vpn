package multihoprelay

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
)

const NodeChainIPCMaximumBytes = 8 << 10
const NodeChainCaptureMaximumBytes = 16 << 10

// The inherited pipes authenticate the original parent and child. Each frame
// additionally binds that owner's complete capture and the caller's fresh
// nonce; a frame cannot authorize a different worker on another pipe.
type NodeChainIPCRequest struct {
	Schema        int    `json:"schema"`
	Operation     string `json:"operation"`
	Nonce         string `json:"nonce"`
	CaptureSHA256 string `json:"capture_sha256"`
}

func (q NodeChainIPCRequest) Valid() bool {
	return q.Schema == 1 && proofID.MatchString(q.Nonce) && proofID.MatchString(q.CaptureSHA256) &&
		(q.Operation == "snapshot" || q.Operation == "bootstrap" || q.Operation == "stop")
}

type NodeChainIPCResponse struct {
	Schema        int               `json:"schema"`
	Operation     string            `json:"operation"`
	Nonce         string            `json:"nonce"`
	CaptureSHA256 string            `json:"capture_sha256"`
	OK            bool              `json:"ok"`
	Receipt       *NodeChainReceipt `json:"receipt,omitempty"`
}

// Valid checks only wire shape. The receiver still checks the exact original
// capture/nonce, monotonic sequence, native readiness and fresh proof receipt.
// A closed acknowledgement is terminal and may never carry a status receipt.
func (r NodeChainIPCResponse) Valid() bool {
	if r.Schema != 1 || !proofID.MatchString(r.Nonce) || !proofID.MatchString(r.CaptureSHA256) {
		return false
	}
	switch r.Operation {
	case "snapshot":
		return r.OK == (r.Receipt != nil)
	case "bootstrap", "stop":
		return r.Receipt == nil
	case "closed":
		return r.OK && r.Receipt == nil
	default:
		return false
	}
}

func DecodeNodeChainIPCRequest(raw []byte) (NodeChainIPCRequest, error) {
	var request NodeChainIPCRequest
	if err := decodeNodeChainJSON(raw, &request, 1024); err != nil || !request.Valid() {
		return NodeChainIPCRequest{}, errors.New("invalid ordered worker request")
	}
	return request, nil
}

func DecodeNodeChainIPCResponse(raw []byte) (NodeChainIPCResponse, error) {
	var response NodeChainIPCResponse
	if err := decodeNodeChainJSON(raw, &response, NodeChainIPCMaximumBytes); err != nil || !response.Valid() {
		return NodeChainIPCResponse{}, errors.New("invalid ordered worker response")
	}
	return response, nil
}

// The staged private capture has the same canonical field rules as the pipe
// protocol. Reading a private file alone does not authorize ambiguous JSON.
func DecodeNodeChainCapture(raw []byte) (NodeChainCapture, error) {
	var capture NodeChainCapture
	if err := decodeNodeChainJSON(raw, &capture, NodeChainCaptureMaximumBytes); err != nil || capture.Validate() != nil {
		return NodeChainCapture{}, errors.New("invalid ordered worker capture")
	}
	return capture.Clone(), nil
}

// Lease requests are independent of private source bytes. Strict decoding is
// shared by the authenticated HTTP adapter and its actual native tests. Only
// a status request may carry status_nonce; descriptor authorization remains a
// separate manager operation on the captured operator registry.
func DecodeNodeChainLeaseRequest(raw []byte, status bool) (NodeChainRequest, string, error) {
	bad := errors.New("invalid ordered lease request")
	var envelope struct {
		NodeChainRequest
		StatusNonce *string `json:"status_nonce,omitempty"`
	}
	if err := decodeNodeChainJSON(raw, &envelope, 4<<10); err != nil || envelope.NodeChainRequest.validateShape() != nil ||
		status != (envelope.StatusNonce != nil) {
		return NodeChainRequest{}, "", bad
	}
	// null and an omitted nonce are distinct wire inputs. Neither may quietly
	// turn a status envelope into a create/delete request.
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || status != (fields["status_nonce"] != nil) {
		return NodeChainRequest{}, "", bad
	}
	if status {
		if !proofID.MatchString(*envelope.StatusNonce) {
			return NodeChainRequest{}, "", bad
		}
		return envelope.NodeChainRequest.Clone(), *envelope.StatusNonce, nil
	}
	return envelope.NodeChainRequest.Clone(), "", nil
}

// encoding/json accepts repeated members and case-insensitive field aliases.
// These private control messages require one canonical field spelling and no
// duplicate at any nesting level, including a member inside a receipt array.
func decodeNodeChainJSON(raw []byte, target any, maximum int) error {
	bad := errors.New("ambiguous ordered control message")
	if len(raw) == 0 || len(raw) > maximum || reflect.TypeOf(target) == nil {
		return bad
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := walkNodeChainJSON(decoder, reflect.TypeOf(target), 0); err != nil {
		return bad
	}
	if _, err := decoder.Token(); err != io.EOF {
		return bad
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || decoder.Decode(new(any)) != io.EOF {
		return bad
	}
	return nil
}

func nodeChainJSONFields(kind reflect.Type) map[string]reflect.Type {
	fields := make(map[string]reflect.Type)
	for index := 0; index < kind.NumField(); index++ {
		field := kind.Field(index)
		if field.PkgPath != "" {
			continue
		}
		tag := strings.Split(field.Tag.Get("json"), ",")[0]
		if tag == "-" {
			continue
		}
		if field.Anonymous && tag == "" && field.Type.Kind() == reflect.Struct {
			for name, typ := range nodeChainJSONFields(field.Type) {
				fields[name] = typ
			}
			continue
		}
		if tag == "" {
			tag = field.Name
		}
		fields[tag] = field.Type
	}
	return fields
}

func nodeChainJSONRequired(kind reflect.Type) map[string]bool {
	fields := make(map[string]bool)
	for index := 0; index < kind.NumField(); index++ {
		field := kind.Field(index)
		if field.PkgPath != "" {
			continue
		}
		parts := strings.Split(field.Tag.Get("json"), ",")
		if parts[0] == "-" {
			continue
		}
		if field.Anonymous && parts[0] == "" && field.Type.Kind() == reflect.Struct {
			for name, required := range nodeChainJSONRequired(field.Type) {
				fields[name] = required
			}
			continue
		}
		name, required := parts[0], true
		if name == "" {
			name = field.Name
		}
		for _, option := range parts[1:] {
			if option == "omitempty" {
				required = false
			}
		}
		fields[name] = required
	}
	return fields
}

func walkNodeChainJSON(decoder *json.Decoder, kind reflect.Type, depth int) error {
	bad := errors.New("invalid ordered control member")
	if depth > 16 {
		return bad
	}
	for kind.Kind() == reflect.Pointer {
		kind = kind.Elem()
	}
	token, err := decoder.Token()
	if err != nil || token == nil {
		return bad
	}
	delim, compound := token.(json.Delim)
	if !compound {
		return nil // The typed decoder below validates scalar type/range/null.
	}
	switch delim {
	case '{':
		if kind.Kind() != reflect.Struct {
			return bad
		}
		fields, seen := nodeChainJSONFields(kind), make(map[string]bool)
		for decoder.More() {
			token, err := decoder.Token()
			key, ok := token.(string)
			child, known := fields[key]
			if err != nil || !ok || !known || seen[key] || len(seen) >= 64 {
				return bad
			}
			seen[key] = true
			if err := walkNodeChainJSON(decoder, child, depth+1); err != nil {
				return err
			}
		}
		for name, required := range nodeChainJSONRequired(kind) {
			if required && !seen[name] {
				return bad
			}
		}
	case '[':
		if kind.Kind() != reflect.Slice && kind.Kind() != reflect.Array {
			return bad
		}
		count := 0
		for decoder.More() {
			if count >= 64 {
				return bad
			}
			count++
			if err := walkNodeChainJSON(decoder, kind.Elem(), depth+1); err != nil {
				return err
			}
		}
	default:
		return bad
	}
	end, err := decoder.Token()
	if err != nil || delim == '{' && end != json.Delim('}') || delim == '[' && end != json.Delim(']') {
		return bad
	}
	return nil
}
