package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

// A captured tunnel implements only dialing. HTTP and TLS continue to own
// framing, certificate verification and the provider's public hostname.
type speedLabTunnelDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type speedLabTunnelDialerKey struct{}
type speedLabTunnelDialCapture struct{ dialer speedLabTunnelDialer }
type speedLabRequestContextKey struct{}

func withSpeedLabTunnelDialer(ctx context.Context, dialer speedLabTunnelDialer) context.Context {
	return context.WithValue(ctx, speedLabTunnelDialerKey{}, speedLabTunnelDialCapture{dialer})
}

type speedLabTunnelTransport struct {
	transport *http.Transport
	owner     context.Context
}

// Dial admission may end when DialContext returns. The successful socket
// remains owned by this request (and its captured path) until response closure.
func speedLabDialLifetime(ctx context.Context) context.Context {
	if lifetime, ok := ctx.Value(speedLabRequestContextKey{}).(context.Context); ok && lifetime != nil {
		return lifetime
	}
	return ctx
}

type speedLabResponseBody struct {
	io.ReadCloser
	finish func()
}

func (b *speedLabResponseBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.finish()
	}
	return n, err
}
func (b *speedLabResponseBody) Close() error {
	err := b.ReadCloser.Close()
	b.finish()
	return err
}

func (t *speedLabTunnelTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	// http.Transport deliberately uses WithoutCancel when it dials. A value
	// retains this exact request context, including http.Client's shorter
	// timeout, through that transformation without changing its URL or Host.
	var lifetime context.Context
	var cancel context.CancelFunc
	if deadline, bounded := t.owner.Deadline(); bounded {
		lifetime, cancel = context.WithDeadline(request.Context(), deadline)
	} else {
		lifetime, cancel = context.WithCancel(request.Context())
	}
	stopOwner := context.AfterFunc(t.owner, func() {
		if t.owner.Err() != context.DeadlineExceeded {
			cancel()
		}
	})
	finish := func() { stopOwner(); cancel() }
	if err := errors.Join(t.owner.Err(), lifetime.Err()); err != nil {
		finish()
		return nil, err
	}
	ctx := context.WithValue(lifetime, speedLabRequestContextKey{}, lifetime)
	response, err := t.transport.RoundTrip(request.Clone(ctx))
	if err != nil {
		finish()
		return response, err
	}
	if response.Body == nil {
		finish()
	} else {
		response.Body = &speedLabResponseBody{ReadCloser: response.Body, finish: finish}
	}
	return response, nil
}
func (t *speedLabTunnelTransport) CloseIdleConnections() { t.transport.CloseIdleConnections() }

func newSpeedLabHTTPClientContext(ctx context.Context, timeout time.Duration) *http.Client {
	client := newSpeedLabHTTPClient(timeout)
	if ctx == nil {
		return client
	}
	capture, present := ctx.Value(speedLabTunnelDialerKey{}).(speedLabTunnelDialCapture)
	if !present {
		return client
	}
	transport := client.Transport.(*http.Transport)
	transport.Proxy = nil
	transport.DialTLS, transport.DialTLSContext = nil, nil
	if transport.TLSClientConfig != nil {
		// The cloned transport may have test/custom defaults. The URL's public
		// hostname and ordinary certificate validation remain authoritative.
		transport.TLSClientConfig.ServerName = ""
		transport.TLSClientConfig.InsecureSkipVerify = false
	}
	transport.DialContext = func(dialCtx context.Context, network, address string) (net.Conn, error) {
		requestCtx, ok := dialCtx.Value(speedLabRequestContextKey{}).(context.Context)
		if !ok || requestCtx == nil || capture.dialer == nil {
			return nil, errors.New("captured speed-test dial has no original request or tunnel")
		}
		var call context.Context
		var cancel context.CancelFunc
		if deadline, bounded := ctx.Deadline(); bounded {
			call, cancel = context.WithDeadline(requestCtx, deadline)
		} else {
			call, cancel = context.WithCancel(requestCtx)
		}
		stopOwner := context.AfterFunc(ctx, func() {
			// The same deadline already bounds call. Do not race its timer
			// by converting DeadlineExceeded into Cancelled.
			if ctx.Err() != context.DeadlineExceeded {
				cancel()
			}
		})
		stopDial := context.AfterFunc(dialCtx, cancel)
		defer func() { stopOwner(); stopDial(); cancel() }()
		if err := errors.Join(ctx.Err(), requestCtx.Err(), dialCtx.Err(), call.Err()); err != nil {
			return nil, err
		}
		call = context.WithValue(call, speedLabRequestContextKey{}, requestCtx)
		connection, err := capture.dialer.DialContext(call, network, address)
		err = errors.Join(err, ctx.Err(), requestCtx.Err(), dialCtx.Err(), call.Err())
		if err != nil {
			if connection != nil {
				err = errors.Join(err, connection.Close())
			}
			return nil, err
		}
		if connection == nil {
			return nil, errors.New("captured speed-test tunnel returned no connection")
		}
		return connection, nil
	}
	client.Transport = &speedLabTunnelTransport{transport: transport, owner: ctx}
	return client
}
