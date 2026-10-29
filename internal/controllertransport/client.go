package controllertransport

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxBody = 8 << 20

// The installed and Portable node-import UI and the shipping bundle handler
// already accept 32 MiB. Keep that request capability separate from response
// limits; no other route or encoded/queried alias acquires the larger budget.
func requestBodyLimit(method, path string) int {
	if method == http.MethodPost && path == "/api/profile/import" {
		return 32 << 20
	}
	return maxBody
}

type Client struct {
	owner      Process
	access     string
	shutdown   string
	base       *url.URL
	http       *http.Client
	transport  *http.Transport
	dial       func(context.Context, string, string) (net.Conn, error)
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
	retired    bool
	operations sync.WaitGroup
	closeOnce  sync.Once
}

type Response struct {
	Status int
	Body   []byte
}

func NewClient(owner Process, pin, access, shutdown string) (*Client, error) {
	return newClient(owner, pin, access, shutdown, BaseURL)
}

// endpoint is private so test listeners can use an OS-selected loopback port.
// Production always uses the exact fixed endpoint above.
func newClient(owner Process, pin, access, shutdown, endpoint string) (*Client, error) {
	if !validSecret(access) || !validOwner(shutdown) {
		return nil, errors.New("the native controller requires independent captured access and shutdown secrets")
	}
	config, err := pinnedTLS(pin, owner)
	if err != nil {
		return nil, err
	}
	base, err := url.Parse(endpoint)
	if err != nil || base.Scheme != "https" || base.Hostname() != "127.0.0.1" || base.Port() == "" ||
		base.User != nil || base.Path != "" || base.RawQuery != "" || base.Fragment != "" || base.Opaque != "" {
		return nil, errors.New("the native controller endpoint is not the captured loopback listener")
	}
	ctx, cancel := context.WithCancel(context.Background())
	client := &Client{owner: owner, access: access, shutdown: shutdown, base: base, ctx: ctx, cancel: cancel}
	client.dial = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	client.transport = &http.Transport{
		Proxy: nil,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("the native controller refuses an unpinned transport")
		},
		DialTLSContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != base.Host {
				return nil, errors.New("the native controller transport refused another destination")
			}
			// net/http may retain a dial after its initiating request is cancelled.
			// Track this native operation separately and bind its full TCP + TLS
			// handshake to the captured client lifetime until it has joined.
			finish, err := client.begin()
			if err != nil {
				return nil, err
			}
			defer finish()
			owned, stop := ownedContext(ctx, client.ctx)
			defer stop()
			bounded, cancel := context.WithTimeout(owned, 5*time.Second)
			defer cancel()
			connection, err := client.dial(bounded, network, address)
			if err != nil {
				return nil, err
			}
			secured := tls.Client(connection, config)
			if err := secured.HandshakeContext(bounded); err != nil {
				_ = secured.Close()
				return nil, err
			}
			if err := bounded.Err(); err != nil {
				_ = secured.Close()
				return nil, err
			}
			if err := owner.Alive(); err != nil {
				_ = secured.Close()
				return nil, err
			}
			return secured, nil
		},
		TLSClientConfig:        config,
		TLSHandshakeTimeout:    5 * time.Second,
		ForceAttemptHTTP2:      false,
		DisableCompression:     true,
		MaxResponseHeaderBytes: 16 << 10,
		MaxIdleConns:           2, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second,
	}
	client.http = &http.Client{Transport: client.transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return client, nil
}

func (client *Client) begin() (func(), error) {
	if client == nil {
		return nil, ErrRetired
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.retired {
		return nil, ErrRetired
	}
	if err := client.owner.Alive(); err != nil {
		return nil, err
	}
	client.operations.Add(1)
	return client.operations.Done, nil
}

// Request owns the complete response read, so Close can cancel and join every
// entered operation before dropping its pooled connections. A redirect is never
// followed and a new TLS connection always rechecks the immutable session pin.
func (client *Client) Request(ctx context.Context, method, path string, body []byte, limit int64) (Response, error) {
	return client.request(ctx, method, path, body, limit, "", "", false)
}

func (client *Client) request(ctx context.Context, method, path string, body []byte, limit int64, authorization, challenge string, acceptExitedReceipt bool) (Response, error) {
	if ctx == nil || len(body) > requestBodyLimit(method, path) || limit <= 0 || limit > maxBody ||
		(method != http.MethodGet && method != http.MethodPost && method != http.MethodDelete && method != http.MethodPut) {
		return Response{}, errors.New("the native controller request is not bounded")
	}
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}
	resource, err := url.ParseRequestURI(path)
	if err != nil || resource.IsAbs() || resource.Host != "" || resource.User != nil || resource.Fragment != "" ||
		resource.Opaque != "" || !strings.HasPrefix(resource.Path, "/api/") || strings.Contains(resource.Path, "\\") ||
		strings.Contains(resource.Path, "/../") || strings.Contains(resource.Path, "/./") {
		return Response{}, errors.New("the native controller request escaped its local API")
	}
	finish, err := client.begin()
	if err != nil {
		return Response{}, err
	}
	defer finish()
	requestContext, stop := ownedContext(ctx, client.ctx)
	defer stop()
	target := *client.base
	target.Path, target.RawPath, target.RawQuery = resource.Path, resource.RawPath, resource.RawQuery
	request, err := http.NewRequestWithContext(requestContext, method, target.String(), bytes.NewReader(body))
	if err != nil {
		return Response{}, err
	}
	if authorization == "" {
		authorization = "Bearer " + client.access
	}
	request.Header.Set("Authorization", authorization)
	request.Header.Set("Content-Type", "application/json")
	if challenge != "" {
		request.Header.Set("X-RouterVPN-Challenge", challenge)
	}
	response, err := client.http.Do(request)
	if err != nil {
		return Response{}, err
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return Response{}, errors.New("the captured native controller returned a forbidden redirect")
	}
	if response.ContentLength > limit {
		return Response{}, errors.New("the native controller response exceeds its captured limit")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return Response{}, errors.Join(err, errors.New("the native controller response is incomplete or oversized"))
	}
	if err := requestContext.Err(); err != nil {
		return Response{}, err
	}
	if !acceptExitedReceipt {
		if err := client.owner.Alive(); err != nil {
			return Response{}, err
		}
	}
	return Response{Status: response.StatusCode, Body: raw}, nil
}

func (client *Client) Close() error {
	if client == nil {
		return nil
	}
	client.closeOnce.Do(func() {
		client.mu.Lock()
		client.retired = true
		client.cancel()
		client.mu.Unlock()
		client.transport.CloseIdleConnections()
		client.operations.Wait()
		client.transport.CloseIdleConnections()
	})
	return nil
}

func mac(secret, message string) string {
	hash := hmac.New(sha256.New, []byte(secret))
	_, _ = hash.Write([]byte(message))
	return hex.EncodeToString(hash.Sum(nil))
}

// VerifyIdentity preserves the shared native identity schema and HMAC while
// requiring the pinned TLS connection before even the challenge is transmitted.
func (client *Client) VerifyIdentity(ctx context.Context) error {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	challenge := hex.EncodeToString(nonce[:])
	authorization := "RouterVPN-Identity " + mac(client.access, "routervpn-controller-identity-request\n"+challenge)
	response, err := client.request(ctx, http.MethodGet, "/api/controller/identity", nil, 2048, authorization, challenge, false)
	if err != nil {
		return err
	}
	var identity struct {
		Schema    int    `json:"schema"`
		PID       int    `json:"process_id"`
		Challenge string `json:"challenge"`
		Proof     string `json:"proof"`
	}
	if response.Status != http.StatusOK || exactObject(response.Body, &identity, "schema", "process_id", "challenge", "proof") != nil ||
		identity.Schema != 1 || identity.PID != int(client.owner.PID()) || identity.Challenge != challenge ||
		subtle.ConstantTimeCompare([]byte(identity.Proof), []byte(mac(client.access, "routervpn-controller-identity-response\n"+strconv.Itoa(identity.PID)+"\n"+challenge))) != 1 {
		return errors.New("the native controller did not prove its captured process identity")
	}
	return nil
}

// Shutdown accepts only the exact terminal receipt. Process exit may race a
// fully received, authenticated receipt; the caller still independently joins
// its retained process handle. Mere process death is never cleanup evidence.
func (client *Client) Shutdown(ctx context.Context) error {
	request, _ := json.Marshal(struct {
		Schema int    `json:"schema"`
		PID    int    `json:"process_id"`
		Token  string `json:"owner_token"`
	}{1, int(client.owner.PID()), client.shutdown})
	response, err := client.request(ctx, http.MethodPost, "/api/controller/shutdown", request, 2048, "", "", true)
	if err != nil {
		return err
	}
	var receipt struct {
		Schema int    `json:"schema"`
		PID    int    `json:"process_id"`
		Token  string `json:"owner_token"`
		Closed bool   `json:"closed"`
	}
	if response.Status != http.StatusOK || exactObject(response.Body, &receipt, "schema", "process_id", "owner_token", "closed") != nil ||
		receipt.Schema != 1 || receipt.PID != int(client.owner.PID()) || !receipt.Closed ||
		subtle.ConstantTimeCompare([]byte(receipt.Token), []byte(client.shutdown)) != 1 {
		return errors.New("the native controller has not acknowledged this owner's complete cleanup")
	}
	return nil
}

func exactObject(raw []byte, target any, keys ...string) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return errors.New("native controller receipt is not one object")
	}
	wanted := make(map[string]bool, len(keys))
	for _, key := range keys {
		wanted[key] = true
	}
	seen := make(map[string]bool, len(keys))
	for decoder.More() {
		token, err := decoder.Token()
		key, valid := token.(string)
		if err != nil || !valid || !wanted[key] || seen[key] {
			return errors.New("native controller receipt has an extra or duplicated field")
		}
		seen[key] = true
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return err
		}
	}
	last, err := decoder.Token()
	if err != nil || last != json.Delim('}') || len(seen) != len(wanted) {
		return errors.New("native controller receipt omitted a required field")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("native controller receipt contains trailing data")
	}
	return json.Unmarshal(raw, target)
}
