package common

import (
	"fmt"
	"strings"
)

const (
	StartLayerOff                = "off"
	StartLayerAES256GCM          = "aes-256-gcm"
	StartLayerAES256GCMXOR       = "aes-256-gcm+xor-whitening"
	StartLayerAES256GCMTransport = "2022-blake3-aes-256-gcm"
)

var StartLayerSupportedRawModes = []string{
	"shadowsocks",
	"hysteria2",
	"naive-h2",
	"naive-h3",
}

// NormalizeStartLayerMode canonicalizes the optional pre-tunnel start layer.
//
// Security comes from the vetted Shadowsocks 2022 AES-256-GCM AEAD transport.
// XOR is deliberately modeled only as optional whitening/obfuscation layered
// with that authenticated transport. XOR by itself is rejected and must never
// be counted as encryption or used as a replacement for AEAD authentication.
func NormalizeStartLayerMode(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "_", "-")
	value = strings.ReplaceAll(value, " ", "")
	switch value {
	case "", "off", "none", "disabled":
		return StartLayerOff, nil
	case "aes", "aes256", "aes-256", "aes-gcm", "aes256-gcm", "aes-256-gcm", "ss2022-aes-256-gcm", "shadowsocks-2022-aes-256-gcm":
		return StartLayerAES256GCM, nil
	case "aes+xor", "xor+aes", "aes-256-gcm+xor", "xor+aes-256-gcm", "aes-256-gcm+xor-whitening", "xor-whitening+aes-256-gcm":
		return StartLayerAES256GCMXOR, nil
	case "xor", "xor-only", "xor-whitening":
		return "", fmt.Errorf("XOR whitening is obfuscation only and requires the authenticated AES-256-GCM start layer")
	default:
		return "", fmt.Errorf("unsupported start layer %q", value)
	}
}

func StartLayerSupportsRawMode(modeID string) bool {
	modeID = strings.ToLower(strings.TrimSpace(modeID))
	for _, candidate := range StartLayerSupportedRawModes {
		if modeID == candidate {
			return true
		}
	}
	return false
}

func StartLayerHasAuthenticatedEncryption(mode string) bool {
	mode, err := NormalizeStartLayerMode(mode)
	return err == nil && (mode == StartLayerAES256GCM || mode == StartLayerAES256GCMXOR)
}

func StartLayerHasXORWhitening(mode string) bool {
	mode, err := NormalizeStartLayerMode(mode)
	return err == nil && mode == StartLayerAES256GCMXOR
}

func StartLayerRequiresAES256GCM(mode string) bool {
	return StartLayerHasAuthenticatedEncryption(mode)
}
