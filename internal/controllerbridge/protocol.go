// Package controllerbridge carries the native Windows UI's bounded local API
// operations over its independently authenticated launcher pipe. Authentication
// precedes Serve: a pipe name or this framing is never authority to use a bearer.
package controllerbridge

import (
	"encoding/binary"
	"errors"
	"net/http"
	"net/url"
	"path"
	"strings"
	"unicode/utf8"
)

const (
	HeaderSize           = 32
	Request              = 1
	Cancel               = 2
	Response             = 3
	Failure              = 4
	Cancelled            = 5
	MaxBody              = 8 << 20
	MaxImport            = 32 << 20
	MaxPath              = 2048
	MaxPending           = 32
	MaxReserved          = 64 << 20
	MaxTimeoutMS         = 900000
	MaxSpeedLabTimeoutMS = 960000
)

var ErrProtocol = errors.New("the captured native UI channel received an invalid frame")

// Header has one fixed binary encoding; no field can be repeated, omitted, or
// reinterpreted by JSON parsers on opposite sides of the pipe.
type Header struct {
	Kind          uint8
	Method        uint8
	Status        uint16
	ID            uint64
	TimeoutMS     uint32
	PathLength    uint16
	BodyLength    uint32
	ResponseLimit uint32
}

func (h Header) valid() bool {
	if h.ID == 0 {
		return false
	}
	switch h.Kind {
	case Request:
		return h.Method >= 1 && h.Method <= 4 && h.Status == 0 && h.TimeoutMS > 0 && h.TimeoutMS <= MaxSpeedLabTimeoutMS &&
			h.PathLength > 0 && h.PathLength <= MaxPath && h.BodyLength <= MaxImport && h.ResponseLimit > 0 && h.ResponseLimit <= MaxBody
	case Cancel, Cancelled:
		return h.Method == 0 && h.Status == 0 && h.TimeoutMS == 0 && h.PathLength == 0 && h.BodyLength == 0 && h.ResponseLimit == 0
	case Response:
		return h.Method == 0 && h.Status >= 100 && h.Status <= 599 && h.TimeoutMS == 0 && h.PathLength == 0 && h.BodyLength <= MaxBody && h.ResponseLimit == 0
	case Failure:
		return h.Method == 0 && h.Status == 0 && h.TimeoutMS == 0 && h.PathLength == 0 && h.BodyLength > 0 && h.BodyLength <= 4096 && h.ResponseLimit == 0
	}
	return false
}

func (h Header) Encode() ([HeaderSize]byte, error) {
	var value [HeaderSize]byte
	if !h.valid() {
		return value, ErrProtocol
	}
	copy(value[:4], "RVB1")
	value[4], value[5] = h.Kind, h.Method
	binary.BigEndian.PutUint16(value[6:8], h.Status)
	binary.BigEndian.PutUint64(value[8:16], h.ID)
	binary.BigEndian.PutUint32(value[16:20], h.TimeoutMS)
	binary.BigEndian.PutUint16(value[20:22], h.PathLength)
	binary.BigEndian.PutUint32(value[24:28], h.BodyLength)
	binary.BigEndian.PutUint32(value[28:32], h.ResponseLimit)
	return value, nil
}

func DecodeHeader(value []byte) (Header, error) {
	if len(value) != HeaderSize || string(value[:4]) != "RVB1" || value[22] != 0 || value[23] != 0 {
		return Header{}, ErrProtocol
	}
	h := Header{Kind: value[4], Method: value[5], Status: binary.BigEndian.Uint16(value[6:8]),
		ID: binary.BigEndian.Uint64(value[8:16]), TimeoutMS: binary.BigEndian.Uint32(value[16:20]),
		PathLength: binary.BigEndian.Uint16(value[20:22]), BodyLength: binary.BigEndian.Uint32(value[24:28]),
		ResponseLimit: binary.BigEndian.Uint32(value[28:32])}
	if !h.valid() {
		return Header{}, ErrProtocol
	}
	return h, nil
}

func (h Header) HTTPMethod() string {
	switch h.Method {
	case 1:
		return http.MethodGet
	case 2:
		return http.MethodPost
	case 3:
		return http.MethodPut
	case 4:
		return http.MethodDelete
	}
	return ""
}

// ValidateTarget accepts canonical local API origin-form only. The GUI cannot
// reach launcher-only identity/shutdown endpoints or choose forwarded headers.
// Query values remain encoded exactly as supplied by the existing controls.
func ValidateTarget(target string) error {
	if target == "" || len(target) > MaxPath || !utf8.ValidString(target) || !strings.HasPrefix(target, "/api/") || strings.Contains(target, "#") ||
		strings.Contains(strings.SplitN(target, "?", 2)[0], "%") {
		return ErrProtocol
	}
	for _, value := range target {
		if value < 0x20 || value == 0x7f || value == '\\' {
			return ErrProtocol
		}
	}
	resource, err := url.ParseRequestURI(target)
	if err != nil || resource.IsAbs() || resource.Host != "" || resource.User != nil || resource.Opaque != "" || resource.Fragment != "" ||
		resource.RawPath != "" || !strings.HasPrefix(resource.Path, "/api/") || path.Clean(resource.Path) != resource.Path ||
		strings.HasPrefix(resource.Path, "/api/controller/") || resource.Path == "/api/controller" {
		return ErrProtocol
	}
	for _, value := range resource.Path {
		if value < 0x20 || value == 0x7f || value == '\\' {
			return ErrProtocol
		}
	}
	if _, err := url.ParseQuery(resource.RawQuery); err != nil {
		return ErrProtocol
	}
	return nil
}

func RequestBodyLimit(method, target string) uint32 {
	if method == http.MethodPost && target == "/api/profile/import" {
		return MaxImport
	}
	return MaxBody
}

// The longer captured Tor Compare budget belongs only to the exact Speed Lab
// POST. Header decoding cannot know the target; Serve checks it before reading
// its body or forwarding any operation.
func RequestTimeoutLimit(method, target string) uint32 {
	if method == http.MethodPost && target == "/api/speed-lab/run" {
		return MaxSpeedLabTimeoutMS
	}
	return MaxTimeoutMS
}
