//go:build darwin && routervpn_darwin_guardian

package mobiletor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDesktopPFAnchorProbeBaselineTransition(t *testing.T) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || desktopDarwinTestFixture.Nonce == "" || desktopDarwinPFTestScope == "" {
		t.Fatal("actual isolated native PF baseline fixture is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	capture := desktopSocketFixtureCapture()
	slot, generation := desktopDarwinPFSlot(capture), desktopDarwinPFGeneration(capture)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		// Only this fixture's three individually derived paths can be retired.
		// Drop references before their selected leaves and prove actual absence.
		for _, anchor := range []string{desktopDarwinPFNamespace, slot, generation} {
			present, err := desktopDarwinPFNamespacePresent(cleanup, anchor)
			if err != nil {
				t.Error("native baseline cleanup could not inspect its captured namespace", anchor, err)
				return
			}
			if present {
				if err := desktopDarwinPFNativeReplace(cleanup, anchor, nil); err != nil {
					t.Error("native baseline cleanup did not retire its selected filter queue", anchor, err)
					return
				}
			}
		}
		for _, anchor := range []string{desktopDarwinPFNamespace, slot, generation} {
			if present, err := desktopDarwinPFNamespacePresent(cleanup, anchor); err != nil || present {
				t.Error("native baseline cleanup retained an actual namespace", anchor, err)
			}
		}
	})
	request := DesktopDarwinPFBaselineRequest{Schema: 1, Action: "replace", SessionID: capture.SessionID,
		SourceSHA256: capture.SourceSHA256, Expected: []DesktopDarwinPFBaselineProof{{}}}
	invoke := func(request DesktopDarwinPFBaselineRequest, apply bool) (DesktopDarwinPFBaselineResult, error) {
		t.Helper()
		raw, err := EncodeDesktopDarwinPFBaselineRequest(request)
		if err != nil {
			return DesktopDarwinPFBaselineResult{}, err
		}
		value, err := RunDesktopDarwinPFBaseline(ctx, raw, apply)
		if err != nil {
			return DesktopDarwinPFBaselineResult{}, err
		}
		var result DesktopDarwinPFBaselineResult
		if err := json.Unmarshal(value, &result); err != nil || result.Schema != 1 || result.RequestSHA256 != desktopPFDigest(raw) || result.Applied != apply {
			t.Fatal("actual native baseline response lost its captured request", string(value), err)
		}
		return result, nil
	}
	plan, err := invoke(request, false)
	if err != nil || plan.Previous.Present || !plan.Target.Present {
		t.Fatal("native baseline plan did not retain an absent preimage and compiled target", plan, err)
	}
	if present, err := desktopDarwinPFNamespacePresent(ctx, desktopDarwinPFNamespace); err != nil || present {
		t.Fatal("native baseline planning changed its kernel namespace", err)
	}
	applied, err := invoke(request, true)
	if err != nil || applied.Previous != plan.Previous || applied.Target != plan.Target {
		t.Fatal("native baseline did not apply and prove its exact prior plan", applied, err)
	}
	if _, err := invoke(request, true); err == nil {
		t.Fatal("native baseline accepted a stale absent-owner expectation")
	}
	request.Expected = []DesktopDarwinPFBaselineProof{plan.Previous, plan.Target}
	if retried, err := invoke(request, true); err != nil || retried.Previous != plan.Target || retried.Target != plan.Target {
		t.Fatal("native baseline could not resolve an exact ambiguous commit", retried, err)
	}
	// Install only the selected scoped generation and its own pointer. The
	// fixed baseline utility must not remove that unjoined runtime's policy.
	generationRules, err := desktopPFCompileFilters("block drop out quick " + desktopDarwinPFTestScope + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if err := desktopDarwinPFNativeReplace(ctx, generation, generationRules); err != nil {
		t.Fatal(err)
	}
	pointer, err := desktopPFCompileFilters(desktopDarwinPFPointer(capture))
	if err != nil {
		t.Fatal(err)
	}
	if err := desktopDarwinPFNativeReplace(ctx, slot, pointer); err != nil {
		t.Fatal(err)
	}
	clearRequest := DesktopDarwinPFBaselineRequest{Schema: 1, Action: "clear", Expected: []DesktopDarwinPFBaselineProof{plan.Target}}
	if _, err := invoke(clearRequest, true); err == nil {
		t.Fatal("native baseline removed an unjoined captured runtime")
	}
	if actual, _, err := desktopDarwinPFBaselineRead(ctx); err != nil || actual != plan.Target {
		t.Fatal("native baseline readiness failure changed its retained owner tree", actual, err)
	}
	if actual, err := desktopDarwinPFReadPointer(ctx, capture); err != nil || actual != strings.TrimSpace(desktopDarwinPFPointer(capture)) {
		t.Fatal("native baseline readiness failure changed the captured runtime pointer", actual, err)
	}
	// The owning runtime, not the baseline utility, joins its exact generation.
	if err := desktopDarwinPFNativeReplace(ctx, slot, nil); err != nil {
		t.Fatal(err)
	}
	if err := desktopDarwinPFNativeReplace(ctx, generation, nil); err != nil {
		t.Fatal(err)
	}
	request.SessionID, request.SourceSHA256 = "", ""
	request.Expected = []DesktopDarwinPFBaselineProof{plan.Target}
	inactive, err := invoke(request, true)
	if err != nil || inactive.Target == plan.Target || !inactive.Target.Present {
		t.Fatal("native Always baseline did not retire the old captured session", inactive, err)
	}
	if _, rules, err := desktopDarwinPFBaselineRead(ctx); err != nil || strings.Contains(rules, "anchor ") || !strings.Contains(rules, "block drop out quick") {
		t.Fatal("native inactive baseline borrowed an old runtime or lost its deny", rules, err)
	}
	for _, anchor := range []string{slot, generation} {
		if present, err := desktopDarwinPFNamespacePresent(ctx, anchor); err != nil || present {
			t.Fatal("native inactive baseline retained a captured child namespace", anchor, err)
		}
	}
	clearRequest.Expected = []DesktopDarwinPFBaselineProof{inactive.Target}
	raw, err := EncodeDesktopDarwinPFBaselineRequest(clearRequest)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if _, err := RunDesktopDarwinPFBaseline(cancelled, raw, true); !errors.Is(err, context.Canceled) {
		t.Fatal("native baseline ignored cancellation before its exact removal", err)
	}
	if actual, _, err := desktopDarwinPFBaselineRead(ctx); err != nil || actual != inactive.Target {
		t.Fatal("cancelled native baseline removal changed its retained deny", actual, err)
	}
	removed, err := invoke(clearRequest, true)
	if err != nil || removed.Target.Present {
		t.Fatal("native baseline did not prove exact final retirement", removed, err)
	}
	if present, err := desktopDarwinPFNamespacePresent(ctx, desktopDarwinPFNamespace); err != nil || present {
		t.Fatal("native baseline removal left an empty but live namespace", err)
	}
}
