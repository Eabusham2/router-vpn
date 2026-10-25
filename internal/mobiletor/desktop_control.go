package mobiletor

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// DesktopControl owns the already-connected loopback control socket of one
// standalone child. Authentication never follows a cookie path supplied by the
// peer: the native process owner supplies the captured private cookie and PID.
// The embedded mobile Control constructor and lifecycle remain unchanged.
type DesktopControl struct {
	control   *Control
	operation sync.Mutex
	closed    atomic.Bool
	pid       int
	address   string
	claimed   bool // guarded by operation; one captured session per child
}

// NewDesktopControl transfers ownership of connection, including on failure.
// SAFECOOKIE proves both parties before the child PID, exact sole control
// listener and disabled startup configuration are checked. TAKEOWNERSHIP is
// sent only after those checks, so a stale cookie cannot seize another process.
func NewDesktopControl(ctx context.Context, connection net.Conn, cookie []byte, expectedPID int) (owner *DesktopControl, failure error) {
	if connection == nil {
		return nil, errors.New("desktop Tor requires its captured child control connection")
	}
	defer func() {
		if failure != nil {
			_ = connection.Close()
		}
	}()
	if ctx == nil || len(cookie) != 32 || expectedPID <= 0 || ctx.Err() != nil {
		return nil, errors.New("desktop Tor requires a live context, private cookie and exact child PID")
	}
	address, err := desktopLoopbackAddress(connection.RemoteAddr())
	if err != nil {
		return nil, err
	}
	if _, err := desktopLoopbackAddress(connection.LocalAddr()); err != nil {
		return nil, err
	}
	control, err := NewControl(connection)
	if err != nil {
		return nil, err
	}
	secret := append([]byte(nil), cookie...)
	defer clear(secret)
	nonce := make([]byte, 32)
	defer clear(nonce)
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.New("desktop Tor authentication nonce is unavailable")
	}
	reply, err := control.command(ctx, "AUTHCHALLENGE SAFECOOKIE "+hex.EncodeToString(nonce))
	if err != nil {
		return nil, errors.New("desktop Tor SAFECOOKIE challenge failed")
	}
	serverHash, serverNonce, err := desktopChallenge(reply)
	if err != nil {
		return nil, err
	}
	defer clear(serverHash)
	defer clear(serverNonce)
	expected := desktopCookieHash("server-to-controller", secret, nonce, serverNonce)
	defer clear(expected)
	if !hmac.Equal(serverHash, expected) {
		return nil, errors.New("desktop Tor SAFECOOKIE server identity did not match the captured child")
	}
	response := desktopCookieHash("controller-to-server", secret, nonce, serverNonce)
	defer clear(response)
	if err := control.change(ctx, "AUTHENTICATE "+hex.EncodeToString(response)); err != nil {
		return nil, errors.New("desktop Tor SAFECOOKIE authentication failed")
	}
	owner = &DesktopControl{control: control, pid: expectedPID, address: address}
	if err := owner.verifyProcess(ctx); err != nil {
		return nil, err
	}
	if err := control.configuration(ctx, desktopIdleConfiguration()); err != nil {
		return nil, errors.New("desktop Tor child did not start with disabled networking and empty owned listeners")
	}
	if err := owner.verifyIdle(ctx); err != nil {
		return nil, err
	}
	if err := control.change(ctx, "TAKEOWNERSHIP"); err != nil {
		return nil, errors.New("desktop Tor child refused captured controller ownership")
	}
	return owner, nil
}

func (c *DesktopControl) PID() int        { return c.pid }
func (c *DesktopControl) Address() string { return c.address }

// Closing retires this owner permanently. The native host still has to join its
// Tor child and separately drain PT listeners, proof workers and Box resources;
// a closed control socket alone does not acknowledge complete cleanup.
func (c *DesktopControl) Close() error {
	c.closed.Store(true)
	return c.control.Close()
}

// VerifyProcess rechecks the authenticated socket's process and listener. It
// performs no PID lookup, opens no replacement socket, and cannot adopt a new
// child after an error or cancellation has retired this owner.
func (c *DesktopControl) VerifyProcess(ctx context.Context) (failure error) {
	c.operation.Lock()
	defer c.operation.Unlock()
	defer func() {
		if failure != nil {
			_ = c.Close()
		}
	}()
	if c.closed.Load() || ctx == nil {
		return net.ErrClosed
	}
	return c.verifyProcess(ctx)
}

func (c *DesktopControl) verifyProcess(ctx context.Context) error {
	values, err := c.control.command(ctx, "GETINFO process/pid net/listeners/control")
	if err != nil {
		return err
	}
	actual, err := keyedReply(values, []string{"process/pid", "net/listeners/control"})
	if err != nil || len(actual["process/pid"]) != 1 || len(actual["net/listeners/control"]) != 1 {
		return errors.New("desktop Tor child process readback is incomplete or ambiguous")
	}
	pid, err := strconv.Atoi(actual["process/pid"][0])
	if err != nil || pid != c.pid || strconv.Itoa(pid) != actual["process/pid"][0] {
		return errors.New("desktop Tor control belongs to a different child process")
	}
	listener, err := strconv.Unquote(actual["net/listeners/control"][0])
	if err != nil || listener != c.address {
		return errors.New("desktop Tor child has a different or additional control listener")
	}
	return nil
}

func desktopIdleConfiguration() map[string][]string {
	return withEmptyProxies(map[string][]string{
		"DisableNetwork": {"1"}, "__ReloadTorrcOnSIGHUP": {"0"}, "SocksPort": {"0"}, "UseBridges": {"0"},
		"Bridge": {""}, "ClientTransportPlugin": {""},
	})
}

func (c *DesktopControl) verifyIdle(ctx context.Context) error {
	idle, err := c.idle(ctx)
	if err != nil {
		return err
	}
	if !idle {
		return errors.New("desktop Tor child has unowned connections, cached addresses or listeners")
	}
	return nil
}

func (c *DesktopControl) idle(ctx context.Context) (bool, error) {
	values, err := c.control.command(ctx, "GETINFO "+strings.Join(idleInventories, " "))
	if err != nil {
		return false, err
	}
	actual, err := keyedReply(values, idleInventories)
	if err != nil {
		return false, err
	}
	idle := true
	for _, key := range idleInventories {
		if len(actual[key]) != 1 {
			return false, errors.New("desktop Tor idle inventory is ambiguous")
		}
		if key == "net/listeners/control" {
			if actual[key][0] != strconv.Quote(c.address) {
				return false, errors.New("desktop Tor idle inventory has a different control owner")
			}
		} else if actual[key][0] != "" {
			idle = false
		}
	}
	return idle, nil
}

func desktopLoopbackAddress(address net.Addr) (string, error) {
	if address == nil || address.Network() != "tcp" {
		return "", errors.New("desktop Tor control must be its captured IPv4 loopback TCP socket")
	}
	value := address.String()
	host, text, err := net.SplitHostPort(value)
	port, numberErr := strconv.Atoi(text)
	if err != nil || numberErr != nil || host != "127.0.0.1" || port < 1024 || port > 65535 || strconv.Itoa(port) != text {
		return "", errors.New("desktop Tor control escaped its exact IPv4 loopback listener")
	}
	return value, nil
}

func desktopChallenge(reply []string) ([]byte, []byte, error) {
	failure := errors.New("desktop Tor SAFECOOKIE challenge is malformed or ambiguous")
	if len(reply) != 1 {
		return nil, nil, failure
	}
	fields := strings.Fields(reply[0])
	if len(fields) != 3 || fields[0] != "AUTHCHALLENGE" {
		return nil, nil, failure
	}
	values := map[string][]byte{}
	for _, field := range fields[1:] {
		key, value, ok := strings.Cut(field, "=")
		decoded, err := hex.DecodeString(value)
		if !ok || (key != "SERVERHASH" && key != "SERVERNONCE") || values[key] != nil || err != nil || len(decoded) != 32 {
			return nil, nil, failure
		}
		values[key] = decoded
	}
	return values["SERVERHASH"], values["SERVERNONCE"], nil
}

// SAFECOOKIE's direction-specific HMAC keys and transcript order are defined
// by https://spec.torproject.org/control-spec/commands.html#authchallenge.
func desktopCookieHash(direction string, cookie, clientNonce, serverNonce []byte) []byte {
	hash := hmac.New(sha256.New, []byte("Tor safe cookie authentication "+direction+" hash"))
	_, _ = hash.Write(cookie)
	_, _ = hash.Write(clientNonce)
	_, _ = hash.Write(serverNonce)
	return hash.Sum(nil)
}
