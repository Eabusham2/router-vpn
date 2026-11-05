//go:build linux

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"runtime"
	"syscall"
	"time"
)

// Authentication uses immutable generation images and exact fixed argv, before
// consuming a packet. Ordinary clients cannot enter this privileged role.
func (s *linuxStandardService) imageConnection(c *net.UnixConn) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	select {
	case <-ctx.Done():
		return false
	case <-s.gate:
	}
	a, t := s.imageAuthority, s.imageUpgrade
	terminal := t != nil && (t.phase == "settled" || t.phase == "aborted")
	var old, next *linuxStandardServiceGeneration
	if a != nil {
		old = a.generation
	}
	if t != nil {
		old = t.oldGeneration
		next = t.newGeneration
	}
	s.gate <- struct{}{}
	if old == nil {
		return false
	}
	peer, err := captureLinuxStandardServicePeer(ctx, c, old.imageInfo, []string{old.imagePath, linuxStandardImageUpgradeArgument}, s.namespace)
	role := "coordinator"
	if err != nil && terminal && a != nil && a.generation != old {
		peer, err = captureLinuxStandardServicePeer(ctx, c, a.generation.imageInfo, []string{a.generation.imagePath, linuxStandardImageUpgradeArgument}, s.namespace)
	}
	if err != nil && next != nil {
		peer, err = captureLinuxStandardServicePeer(ctx, c, next.imageInfo, []string{next.imagePath, linuxStandardServiceArgument}, s.namespace)
		role = "successor"
	}
	if err != nil {
		return false
	}
	defer s.workers.Done()
	defer c.Close()
	defer func() {
		<-s.gate
		retained := s.imageUpgrade != nil && (s.imageUpgrade.coordinator == peer || s.imageUpgrade.successor == peer)
		s.gate <- struct{}{}
		if !retained {
			_ = peer.Close()
		}
	}()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	body, files, err := linuxStandardServiceRead(c)
	for _, f := range files {
		_ = f.Close()
	}
	if err != nil || len(files) != 0 {
		return true
	}
	var q linuxStandardServiceRequest
	if linuxStandardServiceDecode(body, &q) != nil || q.ImageUpgrade == nil || q.Schema != 1 || q.BudgetMS < 1 || q.BudgetMS > 120000 {
		return true
	}
	deadline := time.Unix(0, q.DeadlineNS)
	if max := time.Now().Add(time.Duration(q.BudgetMS) * time.Millisecond); max.Before(deadline) {
		deadline = max
	}
	work, stop := context.WithDeadline(context.Background(), deadline)
	defer stop()
	_ = c.SetDeadline(deadline)
	select {
	case <-work.Done():
		return true
	case <-s.gate:
	}
	defer func() { s.gate <- struct{}{} }()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	live, join := linuxStandardServiceChannelLifetime(work, c)
	result, fd, err := s.imageRequest(live, peer, role, q)
	err = errors.Join(err, live.Err(), join(), work.Err())
	response := linuxStandardServiceResponse{Schema: 1, Session: q.Session, Action: q.Action, Complete: err == nil, ImageUpgrade: result}
	if err != nil {
		response.Error = "original image handoff remains incomplete: " + err.Error()
		if len(response.Error) > 2048 {
			response.Error = "original image handoff remains incomplete"
		}
	}
	_ = linuxStandardServiceWrite(c, response, fd)
	if s.quiescing && s.imageUpgrade != nil && (s.imageUpgrade.phase == "settled" || s.imageUpgrade.candidate && s.imageUpgrade.phase == "aborted") {
		s.requestShutdown()
	}
	return true
}

// Each reconnect proves the actual original peer; an identical path is never
// a substitute for the first process/pidfd captured by this operation.
type linuxStandardImageClient struct {
	generation *linuxStandardServiceGeneration
	namespace  os.FileInfo
	peer       *linuxStandardServicePeer
}

func (r *linuxStandardImageClient) call(ctx context.Context, action, session string, q *linuxStandardServiceImageUpgradeRequest) (*linuxStandardServiceImageUpgradeResponse, *os.File, error) {
	deadline, ok := ctx.Deadline()
	if !ok || ctx.Err() != nil {
		return nil, nil, errors.New("image RPC lost original bounded caller")
	}
	if err := r.generation.Current(ctx); err != nil {
		return nil, nil, err
	}
	raw, err := linuxStandardImageDial(ctx, r.generation.socket(linuxStandardServiceDirectory), r.peer != nil)
	if err != nil {
		return nil, nil, err
	}
	defer raw.Close()
	c, ok := raw.(*net.UnixConn)
	if !ok {
		return nil, nil, errors.New("image RPC lost native channel")
	}
	finish, err := linuxStandardServiceDeadline(ctx, c)
	if err != nil {
		return nil, nil, err
	}
	defer finish()
	peer, err := captureLinuxStandardServicePeer(ctx, c, r.generation.imageInfo, []string{r.generation.imagePath, linuxStandardServiceArgument}, r.namespace)
	if err != nil {
		return nil, nil, err
	}
	if r.peer != nil {
		defer peer.Close()
		if r.peer.record != peer.record {
			return nil, nil, errors.New("image RPC original process was replaced")
		}
		if err = r.peer.Current(ctx); err != nil {
			return nil, nil, err
		}
	} else {
		r.peer = peer
	}
	remaining := time.Until(deadline).Milliseconds()
	if remaining < 1 {
		return nil, nil, context.DeadlineExceeded
	}
	if remaining > 120000 {
		remaining = 120000
	}
	request := linuxStandardServiceRequest{Schema: 1, Action: action, Session: session, BudgetMS: remaining, DeadlineNS: deadline.UnixNano(), ImageUpgrade: q}
	if err = linuxStandardServiceWrite(c, request, nil); err != nil {
		return nil, nil, err
	}
	body, files, err := linuxStandardServiceRead(c)
	if err != nil {
		return nil, nil, err
	}
	var file *os.File
	if len(files) == 1 {
		file = files[0]
	}
	keep := false
	defer func() {
		if !keep && file != nil {
			_ = file.Close()
		}
	}()
	var response linuxStandardServiceResponse
	if err = linuxStandardServiceDecode(body, &response); err != nil {
		return nil, nil, err
	}
	if response.Schema != 1 || response.Action != action || response.Session != session || response.Complete == (response.Error != "") || response.Startup != nil || response.MTU != nil || response.Reverse != nil || response.Transfer != nil || response.Protection != nil || response.ImageUpgrade == nil || file != nil && action != "image-join" {
		return nil, nil, errors.New("image RPC returned another operation scope")
	}
	if !response.Complete {
		return response.ImageUpgrade, nil, errors.New(response.Error)
	}
	terminal := action == "image-settle" && response.ImageUpgrade.Phase == "settled" || action == "image-code-restored" && response.ImageUpgrade.Phase == "aborted"
	if terminal {
		dead, e := peer.Retired()
		if e != nil {
			return response.ImageUpgrade, nil, e
		}
		if !dead {
			if e = peer.Current(ctx); e != nil {
				return response.ImageUpgrade, nil, e
			}
		}
	} else if err = peer.Current(ctx); err != nil {
		return response.ImageUpgrade, nil, err
	}
	keep = true
	return response.ImageUpgrade, file, ctx.Err()
}

// Only a failed initial connect carries this marker. Missing source files,
// generation readback and authenticated peer failures never enter this class.
type linuxStandardImageListenerPending struct{ cause error }

func (e *linuxStandardImageListenerPending) Error() string {
	return "original image listener has not bound yet: " + e.cause.Error()
}
func (e *linuxStandardImageListenerPending) Unwrap() error { return e.cause }
func linuxStandardImageDial(ctx context.Context, path string, captured bool) (net.Conn, error) {
	connection, err := (&net.Dialer{}).DialContext(ctx, "unixpacket", path)
	if err != nil && !captured && (errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED)) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &linuxStandardImageListenerPending{err}
	}
	return connection, err
}
func linuxStandardImageWaitForListener(ctx context.Context, attempt func() (*linuxStandardServiceImageUpgradeResponse, error)) (*linuxStandardServiceImageUpgradeResponse, error) {
	var ticker *time.Ticker
	defer func() {
		if ticker != nil {
			ticker.Stop()
		}
	}()
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		reply, err := attempt()
		if _, pending := err.(*linuxStandardImageListenerPending); !pending {
			return reply, err
		}
		if ticker == nil {
			ticker = time.NewTicker(10 * time.Millisecond)
		}
		select {
		case <-ctx.Done():
			return reply, ctx.Err()
		case <-ticker.C:
		}
	}
}
