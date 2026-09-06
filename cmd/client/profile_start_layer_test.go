package main

import (
	"testing"

	"router-vpn/internal/common"
)

func TestApplyProfileSettingsNormalizesStartLayer(t *testing.T) {
	profile := common.RouterProfile{ID: "home", NodeKind: "router-vpn", StartLayer: common.StartLayerOff}
	value := "xor + aes-256-gcm"
	updated, err := applyProfileSettings(profile, profileSettingsRequest{StartLayer: &value})
	if err != nil {
		t.Fatal(err)
	}
	if updated.StartLayer != common.StartLayerAES256GCMXOR {
		t.Fatalf("start layer = %q, want %q", updated.StartLayer, common.StartLayerAES256GCMXOR)
	}
}

func TestApplyProfileSettingsRejectsXOROnly(t *testing.T) {
	profile := common.RouterProfile{ID: "home", NodeKind: "router-vpn"}
	value := "xor"
	updated, err := applyProfileSettings(profile, profileSettingsRequest{StartLayer: &value})
	if err == nil {
		t.Fatalf("XOR-only start layer unexpectedly accepted: %+v", updated)
	}
	if updated.StartLayer != profile.StartLayer {
		t.Fatalf("failed start-layer update mutated profile: got %q want %q", updated.StartLayer, profile.StartLayer)
	}
}

func TestStartLayerEncryptionTruth(t *testing.T) {
	if common.StartLayerHasAuthenticatedEncryption(common.StartLayerOff) {
		t.Fatal("off start layer counted as authenticated encryption")
	}
	if !common.StartLayerHasAuthenticatedEncryption(common.StartLayerAES256GCM) {
		t.Fatal("AES-256-GCM start layer was not counted as authenticated encryption")
	}
	if !common.StartLayerHasAuthenticatedEncryption(common.StartLayerAES256GCMXOR) {
		t.Fatal("AES+XOR start layer lost its authenticated AES encryption property")
	}
	if common.StartLayerHasXORWhitening(common.StartLayerAES256GCM) {
		t.Fatal("plain AES start layer unexpectedly reports XOR whitening")
	}
	if !common.StartLayerHasXORWhitening(common.StartLayerAES256GCMXOR) {
		t.Fatal("AES+XOR start layer did not report XOR whitening")
	}
}
