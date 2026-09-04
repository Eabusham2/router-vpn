package main

import (
	"math"
	"strings"
	"testing"
)

func float64ptr(v float64) *float64 { return &v }

func TestTypedExternalProfileBuilderPreservesExplicitRealCoordinates(t *testing.T) {
	q := createRequestFor("socks5")
	q.Location = "Austin, TX"
	q.Latitude = float64ptr(30.2672)
	q.Longitude = float64ptr(-97.7431)
	p, err := externalProfileFromCreateRequest(q)
	if err != nil { t.Fatal(err) }
	if p.Location != "Austin, TX" || p.Latitude != 30.2672 || p.Longitude != -97.7431 {
		t.Fatalf("real external-node coordinates were not preserved: %+v", p)
	}
}

func TestTypedExternalProfileBuilderPreservesExplicitZeroCoordinates(t *testing.T) {
	q := createRequestFor("https-connect")
	q.Location = "0°, 0°"
	q.Latitude = float64ptr(0)
	q.Longitude = float64ptr(0)
	p, err := externalProfileFromCreateRequest(q)
	if err != nil { t.Fatal(err) }
	if p.Location != "0°, 0°" || p.Latitude != 0 || p.Longitude != 0 {
		t.Fatalf("explicit zero coordinates were treated as absent: %+v", p)
	}
}

func TestTypedExternalProfileBuilderRequiresCoordinatePair(t *testing.T) {
	q := createRequestFor("socks5")
	q.Latitude = float64ptr(30)
	if _, err := externalProfileFromCreateRequest(q); err == nil || !strings.Contains(err.Error(), "supplied together") {
		t.Fatalf("latitude without longitude was accepted: %v", err)
	}
	q = createRequestFor("socks5")
	q.Longitude = float64ptr(-97)
	if _, err := externalProfileFromCreateRequest(q); err == nil || !strings.Contains(err.Error(), "supplied together") {
		t.Fatalf("longitude without latitude was accepted: %v", err)
	}
}

func TestTypedExternalProfileBuilderRejectsInvalidCoordinates(t *testing.T) {
	for _, tc := range []struct{ lat, lon float64 }{
		{91, 0}, {-91, 0}, {0, 181}, {0, -181}, {math.NaN(), 0}, {0, math.Inf(1)},
	} {
		q := createRequestFor("hysteria2")
		q.Latitude, q.Longitude = float64ptr(tc.lat), float64ptr(tc.lon)
		if _, err := externalProfileFromCreateRequest(q); err == nil || !strings.Contains(err.Error(), "coordinates") {
			t.Fatalf("invalid coordinates (%v,%v) were accepted: %v", tc.lat, tc.lon, err)
		}
	}
}

func TestTypedExternalProfileBuilderRejectsUnsafeLocationLabel(t *testing.T) {
	q := createRequestFor("socks5")
	q.Location = "Austin\nInjected"
	if _, err := externalProfileFromCreateRequest(q); err == nil || !strings.Contains(err.Error(), "location label") {
		t.Fatalf("unsafe location label was accepted: %v", err)
	}
}
