//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

const linuxStandardServiceArgument = "--linux-standard-owner-service"
const linuxStandardServiceDirectory = "/run/router-vpn-standard-owner"
const linuxStandardServiceSocket = linuxStandardServiceDirectory + "/control.sock"
const linuxStandardServicePacketLimit = 64 << 10

type linuxStandardServiceRequest struct {
	Schema          int                             `json:"schema"`
	Action          string                          `json:"action"`
	Session         string                          `json:"session"`
	BudgetMS        int64                           `json:"budget_ms"`
	DeadlineNS      int64                           `json:"deadline_ns"`
	Directory       string                          `json:"directory,omitempty"`
	ConfigSHA256    string                          `json:"config_sha256,omitempty"`
	ProfileID       string                          `json:"profile_id,omitempty"`
	ProfileSHA256   string                          `json:"profile_sha256,omitempty"`
	NetworkID       string                          `json:"network_id,omitempty"`
	RouterID        string                          `json:"router_id,omitempty"`
	Endpoint        string                          `json:"endpoint,omitempty"`
	RuntimeMode     string                          `json:"runtime_mode,omitempty"`
	Base            string                          `json:"base,omitempty"`
	Release         bool                            `json:"release,omitempty"`
	ProfileRevision string                          `json:"profile_revision,omitempty"`
	ResultRevision  string                          `json:"result_revision,omitempty"`
	MTU             *linuxStandardServiceMTURequest `json:"mtu,omitempty"`
}

type linuxStandardServiceResponse struct {
	Startup             *linuxStandardServiceStartup        `json:"startup,omitempty"`
	authenticatedPeer   *linuxStandardServicePeer           // local original witness; never decoded
	transmittedDeadline int64                               // local RPC bound; never decoded from service data
	Schema              int                                 `json:"schema"`
	Session             string                              `json:"session"`
	Action              string                              `json:"action"`
	Complete            bool                                `json:"complete"`
	Error               string                              `json:"error,omitempty"`
	Protection          *linuxStandardServiceProtectionData `json:"protection,omitempty"`
	MTU                 *linuxStandardServiceMTUResponse    `json:"mtu,omitempty"`
}

func linuxStandardServiceDecode(body []byte, target any) error {
	if len(body) == 0 || len(body) > linuxStandardServicePacketLimit {
		return errors.New("standard owner service packet exceeded its bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(body, canonical) {
		return errors.Join(err, errors.New("standard owner service packet is not canonical and unambiguous"))
	}
	return nil
}

func linuxStandardServiceRead(connection *net.UnixConn) (body []byte, files []*os.File, failure error) {
	if connection == nil {
		return nil, nil, errors.New("standard owner service lost its original channel")
	}
	packet := make([]byte, linuxStandardServicePacketLimit+1)
	control := make([]byte, syscall.CmsgSpace(4*4))
	raw, err := connection.SyscallConn()
	if err != nil {
		return nil, nil, err
	}
	var n, ancillary, flags int
	var nativeErr error
	err = raw.Read(func(fd uintptr) bool {
		var failure error
		n, ancillary, flags, _, failure = syscall.Recvmsg(int(fd), packet, control, syscall.MSG_CMSG_CLOEXEC)
		if failure == syscall.EAGAIN || failure == syscall.EWOULDBLOCK {
			return false
		}
		nativeErr = failure
		return true
	})
	if err != nil || nativeErr != nil {
		return nil, nil, errors.Join(err, nativeErr)
	}
	defer func() {
		if failure != nil {
			for _, file := range files {
				_ = file.Close()
			}
			files = nil
		}
	}()
	messages, err := syscall.ParseSocketControlMessage(control[:ancillary])
	if err != nil {
		return nil, files, err
	}
	for _, message := range messages {
		if message.Header.Level != syscall.SOL_SOCKET || message.Header.Type != syscall.SCM_RIGHTS {
			failure = errors.Join(failure, errors.New("standard owner service received unrelated native authority"))
			continue
		}
		descriptors, err := syscall.ParseUnixRights(&message)
		if err != nil {
			failure = errors.Join(failure, err)
			continue
		}
		for _, descriptor := range descriptors {
			syscall.CloseOnExec(descriptor)
			files = append(files, os.NewFile(uintptr(descriptor), "original-standard-request-directory"))
		}
	}
	if failure != nil {
		return nil, files, failure
	}
	if n < 1 || n > linuxStandardServicePacketLimit || flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 || len(files) > 1 {
		return nil, files, errors.New("standard owner service packet or descriptor inventory was incomplete")
	}
	return packet[:n], files, nil
}

func linuxStandardServiceWrite(connection *net.UnixConn, value any, file *os.File) error {
	body, err := json.Marshal(value)
	if err != nil || len(body) == 0 || len(body) > linuxStandardServicePacketLimit {
		return errors.Join(err, errors.New("standard owner service response exceeded its bound"))
	}
	var rights []byte
	if file != nil {
		rights = syscall.UnixRights(int(file.Fd()))
	}
	n, ancillary, err := connection.WriteMsgUnix(body, rights, nil)
	if err != nil {
		return err
	}
	if n != len(body) || ancillary != len(rights) {
		return errors.New("standard owner service native packet was not completely sent")
	}
	return nil
}

func linuxStandardServiceDeadline(ctx context.Context, connection *net.UnixConn) (func(), error) {
	if ctx == nil || ctx.Err() != nil || connection == nil {
		return nil, errors.New("standard service request was already cancelled")
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(30 * time.Second)
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return nil, err
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(done); _ = connection.SetDeadline(time.Now()) })
	return func() {
		if !stop() {
			<-done
		}
	}, nil
}

// A request has exactly one authenticated packet. The original channel's EOF,
// a second packet, or a receive failure cancels that request while its real
// native work is still running. Joining this reader before replying prevents
// the caller's ordinary post-response close from cancelling completed work.
func linuxStandardServiceChannelLifetime(ctx context.Context, connection *net.UnixConn) (context.Context, func() error) {
	operation, cancel := context.WithCancel(ctx)
	var mu sync.Mutex
	finishing := false
	var channelFailure error
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		_, files, err := linuxStandardServiceRead(connection)
		for _, file := range files {
			_ = file.Close()
		}
		mu.Lock()
		defer mu.Unlock()
		if !finishing {
			channelFailure = errors.Join(err, errors.New("standard service lost its original request channel"))
			cancel()
		}
	}()
	return operation, func() error {
		mu.Lock()
		finishing = true
		mu.Unlock()
		err := connection.SetReadDeadline(time.Now())
		<-joined
		cancel()
		mu.Lock()
		defer mu.Unlock()
		return errors.Join(err, channelFailure)
	}
}
