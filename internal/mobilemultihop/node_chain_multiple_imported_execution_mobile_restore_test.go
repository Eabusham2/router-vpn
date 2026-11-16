package mobilemultihop

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Actual shared compiler, authenticated Manager and proof transport; native TUN/readback remains the explicit original boundary double.
func multipleImportedMobileReadbackFixture(t *testing.T, target, execution string, localWinner bool) (*nodeChainExecutionRuntimeFixture, *nodeChainExecutionReadbackEngine, context.Context) {
	t.Helper()
	f := multipleImportedExecutionRuntimeFixture(t, multipleImportedServerLayouts[1], execution)
	bound, err := f.runtime.projection.MTUPlan()
	if err != nil {
		t.Fatal(err)
	}
	mtu := 1400
	if bound.Original == mtu || bound.Ceiling < mtu {
		t.Fatal("fixture lacks distinct valid native MTU", bound)
	}
	name := "tun42"
	if target == "ios" {
		name = "utun42"
	}
	e := &nodeChainExecutionReadbackEngine{nodeChainExecutionRuntimeEngine: f.engine, issued: NodeChainExecutionTUNReadback{Identity: f.engine.identity, TargetOS: target, TUNTag: bound.TUNTag, ReaderNonce: strings.Repeat("c", 64), ReaderGeneration: 3, InterfaceName: name, InterfaceIndex: 42, MTU: mtu}}
	f.runtime.engine = e
	if localWinner {
		f.engine.localDelay, f.engine.serverDelay = time.Millisecond, 200*time.Millisecond
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	t.Cleanup(cancel)
	if err := f.runtime.Run(ctx); err != nil {
		t.Fatal(err)
	}
	return f, e, ctx
}
func TestMobileNodeChainMultipleImportedExecutionRestoreKeepsOriginalOwnerMTUAndChoice(t *testing.T) {
	for _, target := range []string{"android", "ios"} {
		t.Run(target, func(t *testing.T) {
			setting, winner := "server", "server"
			if target == "ios" {
				setting, winner = "auto", "local"
			}
			f, e, ctx := multipleImportedMobileReadbackFixture(t, target, setting, winner == "local")
			prior := f.runtime.Progress()
			if prior.Execution != winner {
				t.Fatal("fixture did not prove its intended original choice", prior.Execution)
			}
			capture, err := f.runtime.CaptureMobileRestoreContext(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := capture.NewPreparationContext(ctx); err == nil {
				t.Fatal("typed restore bypassed original shared cleanup")
			}
			if _, err := capture.OriginalMultipleImportedPolicyContext(ctx); err == nil {
				t.Fatal("typed policy escaped before original join")
			}
			if err := f.runtime.CloseContext(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := capture.NewPreparationContext(ctx); err == nil {
				t.Fatal("shared closed flag replaced exact native reader retirement")
			}
			nodeChainExecutionReadbackRetire(t, f, e, ctx)
			observations := e.captures.Load()
			prep, err := capture.NewPreparationContext(ctx)
			if err != nil {
				t.Fatal(err)
			}
			cancelled, cancel := context.WithCancel(ctx)
			cancel()
			if _, err := capture.NewPreparationContext(cancelled); err == nil {
				t.Fatal("cancelled caller acquired mobile restore")
			}
			capsule := prep.mobile.multiple
			for _, fault := range []string{"self", "source", "policy", "reader", "config"} {
				originalCapsule := *capsule
				originalReader := prep.mobile.readback
				switch fault {
				case "self":
					capsule.self = nil
				case "source":
					capsule.source = nil
				case "policy":
					capsule.policy = nil
				case "reader":
					prep.mobile.readback.ReaderGeneration++
				case "config":
					capsule.config += " "
				}
				invalid := prep.validateCapture()
				*capsule = originalCapsule
				prep.mobile.readback = originalReader
				if invalid == nil {
					t.Fatal("altered original mobile restore capsule retained authority", fault)
				}
			}
			original := capture.restore.projection
			retainedPolicy, err := capture.OriginalMultipleImportedPolicyContext(ctx)
			if err != nil || retainedPolicy != original.policy {
				t.Fatal("mobile policy accessor replaced original typed pointer", err)
			}
			if _, err := capture.OriginalMultipleImportedPolicyContext(cancelled); err == nil {
				t.Fatal("cancelled caller acquired original typed policy")
			}

			if prep.Source() != original.preparation.Source() || prep.SourceSHA256() != original.preparation.SourceSHA256() ||
				prep.LocalSource() != original.preparation.LocalSource() || prep.LocalSourceSHA256() != original.preparation.LocalSourceSHA256() ||
				prep.ConfigSHA256() == original.preparation.ConfigSHA256() || len(startObject(t, prep.Source())) != 4 {
				t.Fatal("typed restore relabeled config or changed ordinary original source")
			}
			before, after := startObject(t, original.preparation.Config()), startObject(t, prep.Config())
			before["inbounds"].([]any)[0].(map[string]any)["mtu"] = float64(capture.readback.MTU)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("mobile restore changed more than captured system TUN MTU")
			}
			readback, err := prep.MobileRestoreReadback()
			if err != nil || readback != capture.readback {
				t.Fatal("typed preparation lost exact original reader observation", err)
			}
			if _, err := ParseNodeChainExecutionPreparation(prep.Source()); err == nil {
				t.Fatal("generic parser accepted typed MultipleImported")
			}
			if prep.multiple.source != original.preparation.multiple.source || prep.local != original.policy.local {
				t.Fatal("restore replaced original MultipleImported owners")
			}
			ordinary, err := ParseNodeChainMultipleImportedExecutionPreparation(prep.Source())
			if err != nil || ordinary.ConfigSHA256() != original.preparation.ConfigSHA256() || ordinary.ConfigSHA256() == prep.ConfigSHA256() {
				t.Fatal("ordinary parsing reopened private nonzero mobile restore MTU", err)
			}
			if _, err := ordinary.MobileRestoreReadback(); err == nil {
				t.Fatal("ordinary source minted native readback authority")
			}
			injected := startObject(t, prep.Source())
			injected["mobile"] = map[string]any{"restored_mtu": 1280, "target_os": target}
			if _, err := ParseNodeChainMultipleImportedExecutionPreparation(startJSON(t, injected)); err == nil {
				t.Fatal("serialized mobile MTU bypassed opaque restore handling")
			}
			logical, err := capture.SourceContext(ctx)
			if err != nil || logical != original.Source() {
				t.Fatal("restore changed original execution source", err)
			}
			foreign, err := NewNodeChainMultipleImportedExecutionPolicy(original.preparation, original.policy.Source())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := prep.bindMultipleImportedMobileOriginal(ctx, foreign); err == nil {
				t.Fatal("equal-source foreign original policy admitted")
			}
			discoveryEngine := &socksExecutionDiscoveryEngine{nodeChainExecutionRuntimeEngine: cloneNodeChainExecutionRuntimeEngine(f.engine), preparation: prep}
			discovery, err := NewNodeChainExecutionDiscoveryOwner(prep, discoveryEngine)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := discovery.Close(context.Background()); err != nil {
					t.Error(err)
				}
			})
			if _, err := discovery.PlanOriginalContext(ctx, original.policy); err == nil {
				t.Fatal("restoration borrowed original discovery instead of refreshing it")
			}
			if _, err := discovery.Discover(ctx); err != nil {
				t.Fatal("fresh authenticated restoration discovery", err)
			}
			if _, err := discovery.PlanOriginalContext(cancelled, original.policy); err == nil {
				t.Fatal("cancelled discovery adopted original restoration")
			}
			if _, err := discovery.PlanOriginalContext(ctx, foreign); err == nil {
				t.Fatal("fresh discovery borrowed equal-content foreign policy")
			}
			projection, err := discovery.PlanOriginalContext(ctx, original.policy)
			if err != nil {
				t.Fatal(err)
			}
			if err := discovery.Close(ctx); err != nil {
				t.Fatal(err)
			}
			bound, err := projection.MTUPlan()
			oldBound, _ := original.MTUPlan()
			if err != nil || bound.Original != capture.readback.MTU || bound.Ceiling != oldBound.Ceiling || !reflect.DeepEqual(bound.Prefixes, oldBound.Prefixes) {
				t.Fatal("mobile restore changed original prefix envelope", bound, err)
			}
			next := cloneNodeChainExecutionRuntimeEngine(f.engine)
			next.projection = projection
			next.identity.ConfigSHA256 = projection.ConfigSHA256()
			restored, err := NewMobileNodeChainExecutionRestoreRuntime(ctx, capture, projection, next)
			if err != nil {
				t.Fatal(err)
			}
			restored.testTLS = f.trust
			t.Cleanup(func() {
				cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				if err := restored.CloseContext(cleanup); err != nil {
					t.Error(err)
				}
			})
			if err := restored.Run(ctx); err != nil {
				t.Fatal(err)
			}
			progress := restored.Progress()
			if !progress.Ready || progress.Execution != winner || progress.Comparison.Target != prior.Comparison.Target ||
				!reflect.DeepEqual(progress.Comparison.Measurements, prior.Comparison.Measurements) ||
				restored.identity.SourceSHA256 != capture.readback.Identity.SourceSHA256 || restored.identity.ConfigSHA256 != projection.ConfigSHA256() ||
				restored.identity.ConfigSHA256 == capture.readback.Identity.ConfigSHA256 {
				t.Fatal("mobile restore changed saved result or substituted actual config identity")
			}
			next.mu.Lock()
			selections, dnsProofs := len(next.selections), len(next.dnsCalls)
			next.mu.Unlock()
			if selections != 1 || dnsProofs == 0 {
				t.Fatal("mobile restore reran Compare or skipped fresh selected proof", selections, dnsProofs)
			}
			if e.captures.Load() != observations {
				t.Fatal("retired observation queried original closed native reader")
			}
		})
	}
}
