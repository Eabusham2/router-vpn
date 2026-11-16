package mobilemultihop

import (
	"context"
	"reflect"
	"testing"
)

func TestNodeChainMultipleImportedExecutionCarrierOriginalRoot(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		t.Run(mode, func(t *testing.T) {
			original, _, _ := multipleImportedServerFixture(t, multipleImportedServerLayouts[6], mode, "")
			snapshot := serverCarrierSnapshotFixture()
			snapshot.InterfaceMTU = 4000
			carrier := serverCarrierCaptureFixture(t, original, &snapshot)
			if carrier.family != 6 {
				t.Fatal("typed carrier downgraded")
			}
			projected, err := carrier.ProjectContext(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if projected.multiple == nil || projected.carrier != carrier || projected.Source() != original.Source() || !reflect.DeepEqual(projected.proofs, original.proofs) {
				t.Fatal("carrier replaced original source/proof inventory")
			}
			snapshot.InterfaceIndex++
			if carrier.CurrentContext(context.Background()) == nil || projected.validateCapture() == nil {
				t.Fatal("foreign physical owner retained original authority")
			}
		})
	}
}
func TestNodeChainMultipleImportedExecutionCarrierSSFirstRefused(t *testing.T) {
	for _, index := range []int{1, 2, 5, 7} {
		layout := multipleImportedServerLayouts[index]
		t.Run(layout.name, func(t *testing.T) {
			original, _, _ := multipleImportedServerFixture(t, layout, "wg", "")
			reads := 0
			carrier, err := captureNodeChainServerCarrier(context.Background(), original, func(context.Context) (nodeChainServerCarrierSnapshot, error) {
				reads++
				return serverCarrierSnapshotFixture(), nil
			})
			if err == nil || carrier != nil || reads != 0 {
				t.Fatal("invented packet-first physical measurement", err, reads)
			}
		})
	}
}
