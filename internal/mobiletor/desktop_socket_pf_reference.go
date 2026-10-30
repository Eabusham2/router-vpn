package mobiletor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
)

const DesktopDarwinPFReferenceLimit = 128

// A token is only an exact kernel reference identity. This read-only request
// cannot start/stop PF, select an anchor, or acquire another owner's reference.
type DesktopDarwinPFReferenceRequest struct {
	Schema int    `json:"schema"`
	Token  string `json:"token"`
}

type DesktopDarwinPFReferenceResult struct {
	Schema  int    `json:"schema"`
	Token   string `json:"token"`
	Present bool   `json:"present"`
}

func desktopDarwinPFReferenceToken(token string) (uint64, error) {
	value, err := strconv.ParseUint(token, 10, 64)
	if err != nil || value == 0 || strconv.FormatUint(value, 10) != token {
		return 0, errors.New("Darwin PF reference requires one canonical nonzero uint64 token")
	}
	return value, nil
}

func EncodeDesktopDarwinPFReferenceRequest(request DesktopDarwinPFReferenceRequest) ([]byte, error) {
	if _, err := desktopDarwinPFReferenceToken(request.Token); err != nil || request.Schema != 1 {
		return nil, errors.Join(err, errors.New("Darwin PF reference request lost its exact identity"))
	}
	return json.Marshal(request)
}

func ParseDesktopDarwinPFReferenceRequest(raw []byte) (DesktopDarwinPFReferenceRequest, error) {
	var request DesktopDarwinPFReferenceRequest
	if len(raw) == 0 || len(raw) > DesktopDarwinPFReferenceLimit {
		return request, errors.New("Darwin PF reference request exceeds its private bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return DesktopDarwinPFReferenceRequest{}, errors.New("Darwin PF reference request is not a complete record")
	}
	canonical, err := EncodeDesktopDarwinPFReferenceRequest(request)
	if err != nil || !bytes.Equal(canonical, raw) {
		return DesktopDarwinPFReferenceRequest{}, errors.Join(err, errors.New("Darwin PF reference request has missing, duplicate, null or noncanonical fields"))
	}
	return request, nil
}

func RunDesktopDarwinPFReference(ctx context.Context, raw []byte) ([]byte, error) {
	request, err := ParseDesktopDarwinPFReferenceRequest(raw)
	if err != nil || ctx == nil {
		return nil, errors.Join(err, errors.New("Darwin PF reference inspection requires a captured context and token"))
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	token, _ := desktopDarwinPFReferenceToken(request.Token)
	present, err := desktopDarwinPFReferenceExists(ctx, token)
	if err != nil || ctx.Err() != nil {
		return nil, errors.Join(err, ctx.Err())
	}
	return json.Marshal(DesktopDarwinPFReferenceResult{Schema: 1, Token: request.Token, Present: present})
}
