/*
 * Copyright (c) 2015, Yawning Angel <yawning at schwanenlied dot me>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package meeklite

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"

	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/utlsutil"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/base"
	"router-vpn/mobile/torpt/internal/httpowner"
)

const (
	targetsArg = "targets"
	urlArg     = "url"
	frontArg   = "front"
	utlsArg    = "utls"

	maxChanBacklog = 16

	// Constants shamelessly stolen from meek-client.go...
	maxPayloadLength       = 0x10000
	initPollInterval       = 100 * time.Millisecond
	maxPollInterval        = 5 * time.Second
	pollIntervalMultiplier = 1.5
	maxRetries             = 10
	retryDelay             = 100 * time.Millisecond
)

var (
	// ErrNotSupported is the error returned for a unsupported operation.
	ErrNotSupported = errors.New("meek_lite: operation not supported")

	loopbackAddr = net.IPv4(127, 0, 0, 1)
)

type meekClientArgs struct {
	fronts *frontsList
	utls   *utls.ClientHelloID
}

func (ca *meekClientArgs) Network() string {
	return transportName
}

func (ca *meekClientArgs) String() string {
	return transportName + ": " + ca.fronts.String()
}

func newClientArgs(args *pt.Args) (ca *meekClientArgs, err error) {
	ca = &meekClientArgs{}

	targetsStr, ok := args.Get(targetsArg)
	if ok {
		ca.fronts, err = parseTargets(targetsStr)
	} else {
		ca.fronts = NewFrontsList()
		url, ok := args.Get(urlArg)
		if !ok {
			return nil, fmt.Errorf("missing argument '%s'", urlArg)
		}
		front, _ := args.Get(frontArg)
		// RouterVPN's validated bridge grammar accepts a comma-separated
		// front list. Keep every requested front and upstream's random order.
		for _, item := range strings.Split(front, ",") {
			if err = ca.fronts.Add(url, strings.TrimSpace(item)); err != nil {
				break
			}
		}
	}
	if err != nil {
		return nil, err
	}

	// Parse the (optional) utls argument.
	utlsOpt, _ := args.Get(utlsArg)
	if ca.utls, err = utlsutil.ParseClientHelloID(utlsOpt); err != nil {
		return nil, err
	}

	return ca, nil
}

func parseTargets(targetsStr string) (*frontsList, error) {
	fl := NewFrontsList()
	toParse := targetsStr
	for {
		parts := strings.SplitN(toParse, "|", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid targets in bridgline, missing '|': %s", targetsStr)
		}
		url := parts[0]

		parts = strings.SplitN(parts[1], ",", 2)
		for _, front := range strings.Split(parts[0], "+") {
			err := fl.Add(url, front)
			if err != nil {
				return nil, err
			}
		}

		if len(parts) == 1 {
			break
		} else {
			toParse = parts[1]
		}
	}
	return fl, nil
}

type meekConn struct {
	args         *meekClientArgs
	sessionID    string
	roundTripper http.RoundTripper
	httpOwner    *httpowner.Owner
	closeErr     error // published by workerDoneChan

	closeOnce       sync.Once
	workerWrChan    chan []byte
	workerRdChan    chan []byte
	workerCloseChan chan struct{}
	workerDoneChan  chan struct{}
	ctx             context.Context
	cancel          context.CancelFunc
	rdBuf           *bytes.Buffer
}

func (c *meekConn) Read(p []byte) (n int, err error) {
	if c.ctx.Err() != nil {
		return 0, io.ErrClosedPipe
	}
	// If there is data left over from the previous read,
	// service the request using the buffered data.
	if c.rdBuf != nil {
		if c.rdBuf.Len() == 0 {
			panic("empty read buffer")
		}
		n, err = c.rdBuf.Read(p)
		if c.rdBuf.Len() == 0 {
			c.rdBuf = nil
		}
		return
	}

	// Wait for the worker to enqueue more incoming data.
	var b []byte
	select {
	case b = <-c.workerRdChan:
	case <-c.workerCloseChan:
		return 0, io.ErrClosedPipe
	}

	// Ew, an extra copy, but who am I kidding, it's meek.
	buf := bytes.NewBuffer(b)
	n, err = buf.Read(p)
	if buf.Len() > 0 {
		// If there's data pending, stash the buffer so the next
		// Read() call will use it to fulfuill the Read().
		c.rdBuf = buf
	}
	return
}

func (c *meekConn) Write(b []byte) (n int, err error) {
	// Check to see if the connection is actually open.
	select {
	case <-c.workerCloseChan:
		return 0, io.ErrClosedPipe
	default:
	}

	if len(b) == 0 {
		return 0, nil
	}

	// Copy the data to be written to a new slice, since
	// we return immediately after queuing and the peer can
	// happily reuse `b` before data has been sent.
	b2 := append([]byte{}, b...)
	if ok := c.enqueueWrite(b2); !ok {
		// Technically we did enqueue data, but the worker's
		// got closed out from under us.
		return 0, io.ErrClosedPipe
	}
	runtime.Gosched()
	return len(b), nil
}

func (c *meekConn) Close() error {
	c.stop()
	<-c.workerDoneChan
	return c.closeErr
}

// stop signals cancellation without joining. The worker calls this on its
// own error path; public Close always waits until that worker has returned.
func (c *meekConn) stop() {
	c.closeOnce.Do(func() {
		c.cancel()
		c.httpOwner.BeginClose()
		close(c.workerCloseChan)
	})
}

func (c *meekConn) LocalAddr() net.Addr {
	return &net.IPAddr{IP: loopbackAddr}
}

func (c *meekConn) RemoteAddr() net.Addr {
	return c.args
}

func (c *meekConn) SetDeadline(t time.Time) error {
	return ErrNotSupported
}

func (c *meekConn) SetReadDeadline(t time.Time) error {
	return ErrNotSupported
}

func (c *meekConn) SetWriteDeadline(t time.Time) error {
	return ErrNotSupported
}

func (c *meekConn) enqueueWrite(b []byte) (ok bool) {
	select {
	case c.workerWrChan <- b:
		return c.ctx.Err() == nil
	case <-c.workerCloseChan:
		return false
	}
}

func (c *meekConn) roundTrip(sndBuf []byte) (recvBuf []byte, err error) {
	var req *http.Request
	var resp *http.Response

	for retries := 0; retries < maxRetries; retries++ {
		if err := c.ctx.Err(); err != nil {
			return nil, err
		}
		url := *c.args.fronts.URL()
		front := c.args.fronts.Front()

		host := url.Host
		if front != "" {
			url.Host = front
		}

		var body io.Reader
		if len(sndBuf) > 0 {
			body = bytes.NewReader(sndBuf)
		}
		req, err = http.NewRequestWithContext(c.ctx, "POST", url.String(), body)
		if err != nil {
			pt.Log(pt.LogSeverityWarning, "Native meek request could not be created")
			return nil, err
		}
		if front != "" {
			req.Host = host
		}
		req.Header.Set("X-Session-Id", c.sessionID)
		req.Header.Set("User-Agent", "")

		resp, err = c.roundTripper.RoundTrip(req)
		if err != nil {
			if c.ctx.Err() != nil {
				return nil, c.ctx.Err()
			}
			pt.Log(pt.LogSeverityWarning, "Native meek request failed")
			c.args.fronts.Next()
			continue
		}

		if resp.StatusCode == http.StatusOK {
			pt.Log(pt.LogSeverityInfo, "Native meek request succeeded")
			recvBuf, err = io.ReadAll(io.LimitReader(resp.Body, maxPayloadLength))
			resp.Body.Close()
			return
		}

		resp.Body.Close()
		err = fmt.Errorf("status code was %d, not %d", resp.StatusCode, http.StatusOK)
		pt.Log(pt.LogSeverityWarning, "Native meek front rejected the request")
		c.args.fronts.Next()
		select {
		case <-time.After(retryDelay):
		case <-c.workerCloseChan:
			return nil, c.ctx.Err()
		}
	}
	return
}

func (c *meekConn) ioWorker() {
	defer close(c.workerDoneChan)
	defer func() {
		c.stop()
		if closer, ok := c.roundTripper.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
		}
		c.closeErr = c.httpOwner.Close()
	}()
	interval := initPollInterval
	var sndBuf, leftBuf []byte

loop:
	for {
		sndBuf = nil
		select {
		case <-time.After(interval):
			// If the poll interval has elapsed, issue a request.
		case sndBuf = <-c.workerWrChan:
			// If there is data pending a send, issue a request.
		case <-c.workerCloseChan:
			break loop
		}

		// Combine short writes as long as data is available to be
		// sent immediately and it will not put us over the max
		// payload limit.  Any excess data is stored and dispatched
		// as the next request).
		sndBuf = append(leftBuf, sndBuf...)
		wrSz := len(sndBuf)
		for len(c.workerWrChan) > 0 && wrSz < maxPayloadLength {
			b := <-c.workerWrChan
			sndBuf = append(sndBuf, b...)
			wrSz = len(sndBuf)
		}
		if wrSz > maxPayloadLength {
			wrSz = maxPayloadLength
		}

		// Issue a request.
		rdBuf, err := c.roundTrip(sndBuf[:wrSz])
		if err != nil {
			// Welp, something went horrifically wrong.
			break loop
		}

		// Stash the remaining payload if any.
		leftBuf = sndBuf[wrSz:] // Store the remaining data
		if len(leftBuf) == 0 {
			leftBuf = nil
		}

		// Determine the next poll interval.
		if len(rdBuf) > 0 {
			// Received data, enqueue the read.
			select {
			case c.workerRdChan <- rdBuf:
			case <-c.workerCloseChan:
				break loop
			}

			// And poll immediately.
			interval = 0
		} else if wrSz > 0 {
			// Sent data, poll immediately.
			interval = 0
		} else if interval == 0 {
			// Neither sent nor received data after a poll, re-initialize the delay.
			interval = initPollInterval
		} else {
			// Apply a multiplicative backoff.
			interval = time.Duration(float64(interval) * pollIntervalMultiplier)
			if interval > maxPollInterval {
				interval = maxPollInterval
			}
		}

		runtime.Gosched()
	}

	// stop unblocks readers and writers without closing a queue underneath
	// a concurrent sender. Public Close joins the entire deferred cleanup.
}

func newMeekConn(network, addr string, dialFn base.DialFunc, ca *meekClientArgs) (net.Conn, error) {
	id, err := newSessionID()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	owned, err := httpowner.New(ctx, func(_ context.Context, network, address string) (net.Conn, error) {
		return dialFn(network, address)
	})
	if err != nil {
		cancel()
		return nil, err
	}
	var rt http.RoundTripper
	switch ca.utls {
	case nil:
		rt = &http.Transport{DialContext: owned.DialContext}
	default:
		rt = newRoundTripper(func(network, address string) (net.Conn, error) {
			return owned.DialContext(ctx, network, address)
		}, ca.utls)
	}

	conn := &meekConn{
		args:            ca,
		sessionID:       id,
		roundTripper:    rt,
		httpOwner:       owned,
		workerWrChan:    make(chan []byte, maxChanBacklog),
		workerRdChan:    make(chan []byte, maxChanBacklog),
		workerCloseChan: make(chan struct{}),
		workerDoneChan:  make(chan struct{}),
		ctx:             ctx,
		cancel:          cancel,
	}

	// Start the I/O worker.
	go conn.ioWorker()

	return conn, nil
}

func newSessionID() (string, error) {
	var b [64]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	h := sha256.Sum256(b[:])
	return hex.EncodeToString(h[:16]), nil
}

var (
	_ net.Conn = (*meekConn)(nil)
	_ net.Addr = (*meekClientArgs)(nil)
)
