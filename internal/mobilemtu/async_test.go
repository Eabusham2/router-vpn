package mobilemtu

import (
	"strings"
	"testing"
	"time"
)

func TestAsyncStartPublishesImmediateCancellation(t *testing.T) {
	for i := 0; i < 50; i++ {
		controller, owner, _ := fixtureController(t)
		// Keep completion pending even if Start schedules the worker first.
		// Cancellation tests must not depend on goroutine scheduling order.
		owner.blockDownload = make(chan struct{})
		request := strings.Repeat("a", 32)
		if err := controller.Start(request, true); err != nil {
			t.Fatal(err)
		}
		if readStatus(t, controller).Request != request {
			t.Fatal("Start returned before request publication")
		}
		controller.Cancel(request)
		controller.mu.Lock()
		done := controller.done
		controller.mu.Unlock()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("immediate cancellation was lost")
		}
		status := readStatus(t, controller)
		if status.Running || !status.Complete || status.Measured {
			t.Fatal("cancelled request incorrectly adopted a measurement", status)
		}
		if err := controller.Start(request, true); err == nil {
			t.Fatal("completed request identity was reused")
		}
	}
}
func TestAsyncStartAndSynchronousRunShareOneOwner(t *testing.T) {
	controller, owner, _ := fixtureController(t)
	entered := make(chan struct{})
	owner.blockDownload = entered
	request := strings.Repeat("b", 32)
	if err := controller.Start(request, true); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("native measurement did not start")
	}
	if err := controller.Start(strings.Repeat("c", 32), true); err == nil {
		t.Fatal("second asynchronous request accepted")
	}
	if err := controller.Run(strings.Repeat("d", 32), true); err == nil {
		t.Fatal("synchronous request overlapped native request")
	}
	if err := controller.Close(); err != nil {
		t.Fatal(err)
	}
	if controller.Running() {
		t.Fatal("Close returned before asynchronous drain")
	}
	if err := controller.Start(strings.Repeat("e", 32), true); err == nil {
		t.Fatal("stopped owner restarted")
	}
}

// A completed measurement is not a live cancellation. Test this valid ordering
// separately from the blocked worker above rather than relying on CPU timing.
func TestCompletedAsyncMeasurementSurvivesLateCancel(t *testing.T) {
	controller, _, _ := fixtureController(t)
	request := strings.Repeat("f", 32)
	if err := controller.Start(request, true); err != nil {
		t.Fatal(err)
	}
	controller.mu.Lock()
	done := controller.done
	controller.mu.Unlock()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("measurement did not complete")
	}
	before := readStatus(t, controller)
	if before.Running || !before.Complete || !before.Measured {
		t.Fatal("fixture did not complete a valid measurement", before)
	}
	controller.Cancel(request)
	after := readStatus(t, controller)
	if after.Running || !after.Complete || !after.Measured || after.EffectiveMTU != before.EffectiveMTU {
		t.Fatal("late cancellation changed the completed measurement", after)
	}
}
