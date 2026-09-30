package mobilemtu

import (
	"strings"
	"testing"
	"time"
)

func TestAsyncStartPublishesImmediateCancellation(t *testing.T) {
	for i := 0; i < 50; i++ {
		controller, _, _ := fixtureController(t)
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
