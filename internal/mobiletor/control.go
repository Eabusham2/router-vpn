package mobiletor

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Control exclusively owns the native Tor preauthenticated socketpair. It never
// opens or authenticates a public control port.
type Control struct {
	conn      net.Conn
	reader    *bufio.Reader
	mu        sync.Mutex
	operation sync.Mutex
	// A probe retains this claim until its native stream and anchor hold drain.
	// A competing constructor must not wait for (or interrupt) an issued frame.
	lastRelayProbe atomic.Pointer[LastRelayProbe]
}

func NewControl(conn net.Conn) (*Control, error) {
	if conn == nil {
		return nil, errors.New("native Tor owning control socket is missing")
	}
	return &Control{conn: conn, reader: bufio.NewReaderSize(conn, 8192)}, nil
}

func (c *Control) Close() error { return c.conn.Close() }

// Command permits only this owner's bounded control operations. No raw command
// string from a profile or UI reaches the embedded daemon.
func (c *Control) command(ctx context.Context, command string) (reply []string, failure error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// A timed-out or malformed response can leave an unread reply in the stream.
	// Retire it instead of letting the next command consume a stale 250 status.
	defer func() {
		if failure != nil {
			_ = c.conn.Close()
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(10 * time.Second)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	if err := c.conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = c.conn.SetDeadline(time.Now()); close(interrupted) })
	defer func() {
		if !stop() {
			<-interrupted
		}
		_ = c.conn.SetDeadline(time.Time{})
	}()
	if _, err := io.WriteString(c.conn, command+"\r\n"); err != nil {
		return nil, err
	}
	var values []string
	used, events := 0, 0
	readLine := func() (string, error) {
		line, err := c.reader.ReadSlice('\n')
		if err != nil {
			return "", err
		}
		used += len(line)
		if used > 65536 || len(line) < 2 || line[len(line)-2] != '\r' {
			return "", errors.New("invalid or oversized Tor control reply")
		}
		return string(line[:len(line)-2]), nil
	}
	for {
		line, err := readLine()
		if err != nil {
			return nil, err
		}
		if len(line) < 4 {
			return nil, errors.New("invalid Tor control status")
		}
		code, err := strconv.Atoi(line[:3])
		if err != nil {
			return nil, errors.New("invalid Tor control status")
		}
		separator := line[3]
		if separator != ' ' && separator != '-' && separator != '+' {
			return nil, errors.New("unexpected Tor control data reply")
		}
		if code == 650 {
			events++
			if events > 32 || separator == '+' {
				return nil, errors.New("excessive Tor control events")
			}
			continue
		}
		if code != 250 {
			return nil, fmt.Errorf("native Tor control command failed (%d)", code)
		}
		value := line[4:]
		if separator == '+' {
			if !strings.HasSuffix(value, "=") {
				return nil, errors.New("invalid Tor control data header")
			}
			var body []string
			for {
				data, err := readLine()
				if err != nil {
					return nil, err
				}
				if data == "." {
					break
				}
				if strings.HasPrefix(data, ".") {
					if !strings.HasPrefix(data, "..") {
						return nil, errors.New("invalid Tor control dot escaping")
					}
					data = data[1:]
				}
				body = append(body, data)
			}
			value += strings.Join(body, "\n")
		}
		if value != "OK" {
			values = append(values, value)
		}
		if separator == ' ' {
			return values, nil
		}
	}
}

func (c *Control) EnableNetwork(ctx context.Context) error {
	c.operation.Lock()
	defer c.operation.Unlock()
	return c.change(ctx, "SETCONF DisableNetwork=0")
}

func (c *Control) Halt(ctx context.Context) error {
	c.operation.Lock()
	defer c.operation.Unlock()
	return c.change(ctx, "SIGNAL HALT")
}

func (c *Control) change(ctx context.Context, command string) error {
	values, err := c.command(ctx, command)
	if err == nil && len(values) != 0 {
		_ = c.conn.Close()
		return errors.New("unexpected native Tor configuration reply")
	}
	return err
}

type Bootstrap struct {
	Progress           int
	CircuitEstablished bool
	SOCKSAddress       string
}

func (c *Control) Bootstrap(ctx context.Context) (status Bootstrap, failure error) {
	c.operation.Lock()
	defer c.operation.Unlock()
	defer func() {
		if failure != nil {
			_ = c.conn.Close()
		}
	}()
	values, err := c.command(ctx, "GETINFO status/bootstrap-phase status/circuit-established net/listeners/socks")
	if err != nil {
		return Bootstrap{}, err
	}
	result := Bootstrap{Progress: -1}
	seen := map[string]bool{}
	for _, value := range values {
		key, text, ok := strings.Cut(value, "=")
		if !ok || seen[key] {
			return Bootstrap{}, errors.New("ambiguous native Tor bootstrap reply")
		}
		seen[key] = true
		switch key {
		case "status/bootstrap-phase":
			for _, field := range strings.Fields(text) {
				if strings.HasPrefix(field, "PROGRESS=") {
					if result.Progress != -1 {
						return Bootstrap{}, errors.New("ambiguous native Tor progress")
					}
					result.Progress, err = strconv.Atoi(strings.TrimPrefix(field, "PROGRESS="))
					if err != nil || result.Progress < 0 || result.Progress > 100 {
						return Bootstrap{}, errors.New("invalid native Tor progress")
					}
				}
			}
		case "status/circuit-established":
			if text != "0" && text != "1" {
				return Bootstrap{}, errors.New("invalid native Tor circuit state")
			}
			result.CircuitEstablished = text == "1"
		case "net/listeners/socks":
			if text == "" {
				continue
			} // DisableNetwork may close the listener.
			address, e := strconv.Unquote(text)
			if e != nil {
				return Bootstrap{}, errors.New("invalid native Tor SOCKS readback")
			}
			host, port, e := net.SplitHostPort(address)
			n, ne := strconv.Atoi(port)
			if e != nil || ne != nil || host != "127.0.0.1" || n < 1024 || n > 65535 {
				return Bootstrap{}, errors.New("native Tor SOCKS listener escaped loopback")
			}
			result.SOCKSAddress = address
		default:
			return Bootstrap{}, errors.New("unexpected native Tor bootstrap field")
		}
	}
	if len(seen) != 3 || result.Progress < 0 {
		return Bootstrap{}, errors.New("incomplete native Tor bootstrap reply")
	}
	return result, nil
}

// WaitBootstrap proves Tor's circuit state, not the VPN's user traffic path.
// Connected still requires a dynamic Tor-exit proof through the owned final
// outbound after the host has established its real TUN.
func (c *Control) WaitBootstrap(ctx context.Context) (Bootstrap, error) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, err := c.Bootstrap(ctx)
		if err != nil {
			return Bootstrap{}, err
		}
		if status.Progress == 100 && status.CircuitEstablished && status.SOCKSAddress != "" {
			return status, nil
		}
		select {
		case <-ctx.Done():
			return Bootstrap{}, ctx.Err()
		case <-ticker.C:
		}
	}
}
