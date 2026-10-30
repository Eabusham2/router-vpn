//go:build windows

// Package windowsuibridge binds the shared request protocol to an actually
// retained original-user GUI process and the launcher's pinned TLS client.
package windowsuibridge

import (
	"context"
	"errors"
	"time"

	"router-vpn/internal/controllerbridge"
	"router-vpn/internal/controllertransport"
	"router-vpn/internal/windowscontroller"
)

const hello = "RouterVPN-UI-Bridge-v1\n"
const ready = "RouterVPN-UI-Bridge-Ready-v1\n"

var errGUIExited = errors.New("the captured native GUI process exited")

type capturedForwarder struct {
	child  *windowscontroller.GUIChild
	client *controllertransport.Client
}

func (forward capturedForwarder) Request(ctx context.Context, method, path string, body []byte, limit int64) (controllertransport.Response, error) {
	if err := forward.child.Alive(); err != nil {
		return controllertransport.Response{}, err
	}
	response, err := forward.client.Request(ctx, method, path, body, limit)
	if ownerErr := forward.child.Alive(); ownerErr != nil {
		return controllertransport.Response{}, errors.Join(err, ownerErr)
	}
	return response, err
}

// Serve consumes one freshly created pipe for one captured GUIChild. The caller
// retains the child's Job, executable image and shared TLS client until this
// function has joined. This channel never closes another GUI's client or Job.
// Its public hello is read before writer-token proof; no private request or
// bearer is accepted until the exact retained child has authenticated.
func Serve(ctx context.Context, pipe *windowscontroller.Pipe, child *windowscontroller.GUIChild, image *windowscontroller.Image, client *controllertransport.Client) (resultErr error) {
	return ServeReady(ctx, pipe, child, image, client, nil)
}

// ServeReady reports readiness only after the actual retained GUI has proved
// its pipe writer and received the exact ready frame. It is a launcher's local
// observation, never a replacement for process/pipe/TLS authentication.
func ServeReady(ctx context.Context, pipe *windowscontroller.Pipe, child *windowscontroller.GUIChild, image *windowscontroller.Image, client *controllertransport.Client, onReady func()) (resultErr error) {
	if ctx == nil || pipe == nil || child == nil || image == nil || client == nil {
		return errors.New("the native GUI bridge requires its complete captured owners")
	}
	defer func() { resultErr = errors.Join(resultErr, pipe.Close()) }()
	if err := child.Alive(); err != nil {
		return err
	}
	owned, retire := context.WithCancelCause(ctx)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		_, err := child.Wait(owned)
		if owned.Err() == nil {
			retire(errors.Join(errGUIExited, err))
		}
	}()
	defer func() {
		retire(resultErr)
		<-joined
	}()
	// A cold PowerShell process can still be loading Framework and compiling
	// its retained transport before it opens the pipe. Bound that startup
	// separately; it must not consume the authenticated frame exchange budget.
	// Both phases remain tied to this exact child's process and caller context.
	startup, stopStartup := context.WithTimeout(owned, 45*time.Second)
	err := pipe.Accept(startup)
	stopStartup()
	if err != nil {
		return err
	}
	// Cancellation owns this entire partial handshake, never a reusable pipe
	// prefix. The binary frame reader starts only after the exact ready frame.
	handoff, stop := context.WithTimeout(owned, 15*time.Second)
	err = func() error {
		frame, err := pipe.ReadFrame(handoff)
		if err != nil {
			return err
		}
		if string(frame) != hello {
			return errors.New("the native GUI bridge public handshake changed")
		}
		peer, err := child.VerifyPeer(pipe, image)
		if err != nil {
			return err
		}
		if err := peer.Process.Close(); err != nil {
			return err
		}
		if err := child.Alive(); err != nil {
			return err
		}
		return pipe.WriteFrame(handoff, []byte(ready))
	}()
	stop()
	if err != nil {
		return err
	}
	if onReady != nil {
		onReady()
	}
	return controllerbridge.Serve(owned, pipe, capturedForwarder{child: child, client: client})
}
