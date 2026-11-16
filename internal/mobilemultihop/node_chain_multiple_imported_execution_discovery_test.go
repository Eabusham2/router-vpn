package mobilemultihop

import (
	"context"
	"testing"
	"time"
)

func TestNodeChainMultipleImportedExecutionAuthenticatedDiscovery(t *testing.T) {
	for _, index := range []int{1, 2, 5, 6} {
		layout := multipleImportedServerLayouts[index]
		t.Run(layout.name, func(t *testing.T) {
			f := multipleImportedExecutionRuntimeFixture(t, layout, "auto")
			p := f.runtime.projection.preparation
			e := &socksExecutionDiscoveryEngine{nodeChainExecutionRuntimeEngine: f.engine, preparation: p}
			owner, err := NewNodeChainExecutionDiscoveryOwner(p, e)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			defer owner.Close(context.Background())
			if _, err = owner.PlanContext(ctx, f.runtime.projection.policy.Descriptor().SourceSHA256, 32003); err == nil {
				t.Fatal("source-only discovery admitted")
			}
			discovered, err := owner.Discover(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(discovered.Sources) != 1 || discovered.Sources[0].Schema != 6 {
				t.Fatal("authenticated original descriptor missing")
			}
			projection, err := owner.PlanContext(ctx, discovered.Sources[0].SourceSHA256, 32003)
			if err != nil {
				t.Fatal(err)
			}
			if projection.preparation != p || projection.policy.multiple != p.multiple || projection.policy.local != p.local {
				t.Fatal("discovery replaced original owned source")
			}
			if _, err = owner.PlanContext(ctx, discovered.Sources[0].SourceSHA256, 32003); err == nil {
				t.Fatal("same native discovery attempt reused")
			}
			if err = owner.Close(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}
