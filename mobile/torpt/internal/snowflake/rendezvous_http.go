package snowflake_client

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	utlsutil "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/ptutil/utls"
	"router-vpn/mobile/torpt/internal/httpowner"
	"router-vpn/mobile/torpt/internal/meeklite"
)

type httpRendezvous struct {
	mu        sync.Mutex
	closed    bool
	brokerURL *url.URL
	fronts    []string
	hello     *utls.ClientHelloID
	dial      func(context.Context, string, string) (net.Conn, error)
}

func newHTTPRendezvous(broker string, fronts []string, hello string, dial func(context.Context, string, string) (net.Conn, error)) (*httpRendezvous, error) {
	u, err := url.Parse(broker)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Hostname() == "" || u.User != nil || u.Fragment != "" || dial == nil {
		return nil, errors.New("Snowflake broker URL is invalid")
	}
	if len(fronts) == 0 || len(strings.Join(fronts, ",")) > 1024 {
		return nil, errors.New("Snowflake broker front list is invalid")
	}
	for _, front := range fronts {
		if strings.TrimSpace(front) != front || front == "" || strings.ContainsAny(front, "/\\?#@ \t\r\n") {
			return nil, errors.New("Snowflake broker front is invalid")
		}
		parsed, err := url.Parse("https://" + front)
		if err != nil || parsed.Host != front || parsed.Hostname() == "" || parsed.User != nil || len(front) > 253 {
			return nil, errors.New("Snowflake broker front is invalid")
		}
		if parsed.Port() != "" {
			port, err := strconv.Atoi(parsed.Port())
			if err != nil || port < 1 || port > 65535 {
				return nil, errors.New("Snowflake broker front port is invalid")
			}
		}
	}
	u.Scheme = "https"
	var id *utls.ClientHelloID
	if hello != "" {
		parsed, err := utlsutil.NameToUTLSID(hello)
		if err != nil {
			return nil, errors.New("Snowflake TLS fingerprint is unsupported")
		}
		id = &parsed
	}
	return &httpRendezvous{brokerURL: u, fronts: append([]string(nil), fronts...), hello: id, dial: dial}, nil
}
func (r *httpRendezvous) Exchange(ctx context.Context, poll []byte) (result []byte, resultErr error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || ctx == nil || ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	owner, err := httpowner.New(ctx, r.dial)
	if err != nil {
		return nil, err
	}
	var roundTripper http.RoundTripper
	var body io.ReadCloser
	defer func() {
		// Freeze admission before an HTTP cleanup call can wait on a socket.
		// RoundTrip returning does not join its asynchronous dial/TLS/HTTP work.
		owner.BeginClose()
		if body != nil {
			_ = body.Close()
		}
		if roundTripper != nil {
			roundTripper.(interface{ CloseIdleConnections() }).CloseIdleConnections()
		}
		if err := owner.Close(); err != nil {
			result, resultErr = nil, err
		}
	}()
	requestURL := r.brokerURL.ResolveReference(&url.URL{Path: "client"})
	// Preserve explicit broker authentication/query parameters on its client path.
	requestURL.RawQuery = r.brokerURL.RawQuery
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL.String(), bytes.NewReader(poll))
	if err != nil {
		return nil, err
	}
	choice, err := rand.Int(rand.Reader, big.NewInt(int64(len(r.fronts))))
	if err != nil {
		return nil, err
	}
	request.Host = request.URL.Host
	request.URL.Host = r.fronts[choice.Int64()]
	if r.hello != nil {
		roundTripper = meeklite.NewBrokerRoundTripper(func(network, address string) (net.Conn, error) {
			return owner.DialContext(ctx, network, address)
		}, r.hello)
	} else {
		roundTripper = &http.Transport{Proxy: nil, DialContext: owner.DialContext,
			TLSClientConfig: &tls.Config{RootCAs: meeklite.GetRootCAs()}, TLSHandshakeTimeout: 15 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second, ForceAttemptHTTP2: true}
	}
	response, err := roundTripper.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	body = response.Body
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("Snowflake broker refused rendezvous")
	}
	return limitedRead(response.Body, readLimit)
}
func (r *httpRendezvous) Close() { r.mu.Lock(); r.closed = true; r.mu.Unlock() }
func limitedRead(reader io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, io.ErrUnexpectedEOF
	}
	return data, nil
}
