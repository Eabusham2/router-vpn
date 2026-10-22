package dnsmeasure

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"strconv"
	"time"
)

const maxDNSMessage = 16 * 1024

func (s *Service) sample(parent context.Context, endpoint Endpoint) (milliseconds float64, failure error) {
	ctx, cancel := context.WithTimeout(parent, SampleTimeout)
	defer cancel()
	if err := s.valid(ctx); err != nil {
		return 0, err
	}
	start := time.Now()
	if endpoint.Kind == "selected" {
		if err := s.engine.SelectedDNS(ctx); err != nil {
			return 0, err
		}
		if err := s.valid(ctx); err != nil {
			return 0, err
		}
		return float64(time.Since(start).Nanoseconds()) / 1e6, nil
	}
	query, err := newQuery()
	if err != nil {
		return 0, err
	}
	address := net.JoinHostPort(endpoint.Address, strconv.Itoa(endpoint.Port))
	if !AllowedPublicAddress(address) {
		return 0, errors.New("DNS probe destination is outside its fixed catalog")
	}
	raw, err := s.engine.Dial(ctx, address)
	if raw != nil {
		owned := s.own(ctx, raw)
		defer func() {
			if closeErr := owned.Close(); closeErr != nil {
				milliseconds, failure = 0, errors.New("DNS native socket did not close")
			}
		}()
		raw = owned
	}
	if err != nil || raw == nil {
		return 0, errors.New("DNS resolver is unreachable through the captured exit")
	}
	if err := s.valid(ctx); err != nil {
		return 0, err
	}
	deadline, _ := ctx.Deadline()
	if err := raw.SetDeadline(deadline); err != nil {
		return 0, errors.New("DNS socket deadline unavailable")
	}
	connection := raw
	if endpoint.Transport != "tcp" {
		config := &tls.Config{MinVersion: tls.VersionTLS12}
		if s.testTLS != nil {
			config = s.testTLS.Clone()
		}
		config.ServerName = endpoint.ServerName
		config.InsecureSkipVerify = false
		config.MinVersion = tls.VersionTLS12
		if endpoint.Transport == "https" {
			config.NextProtos = []string{"http/1.1"}
		}
		secure := tls.Client(raw, config)
		if err := secure.HandshakeContext(ctx); err != nil {
			return 0, errors.New("DNS resolver certificate or TLS handshake failed")
		}
		connection = secure
	}
	var answer []byte
	if endpoint.Transport == "https" {
		answer, err = httpsExchange(ctx, connection, endpoint, query)
	} else {
		answer, err = framedExchange(connection, query)
	}
	if err != nil || validateAnswer(query, answer) != nil {
		return 0, errors.New("DNS resolver did not return a complete matching usable answer")
	}
	if err := s.valid(ctx); err != nil {
		return 0, err
	}
	return float64(time.Since(start).Nanoseconds()) / 1e6, nil
}
func framedExchange(connection net.Conn, query []byte) ([]byte, error) {
	frame := make([]byte, len(query)+2)
	binary.BigEndian.PutUint16(frame, uint16(len(query)))
	copy(frame[2:], query)
	if _, err := io.Copy(connection, bytes.NewReader(frame)); err != nil {
		return nil, err
	}
	var header [2]byte
	if _, err := io.ReadFull(connection, header[:]); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(header[:]))
	if size < 12 || size > maxDNSMessage {
		return nil, errors.New("invalid DNS frame size")
	}
	answer := make([]byte, size)
	_, err := io.ReadFull(connection, answer)
	return answer, err
}
func httpsExchange(ctx context.Context, connection net.Conn, endpoint Endpoint, query []byte) ([]byte, error) {
	// Write HTTP directly to the proved TLS connection. No HTTP default dialer,
	// proxy, redirect, hostname lookup, connection pool or background reader exists.
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+endpoint.ServerName+endpoint.Path, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	request.Close = true
	request.Header.Set("Content-Type", "application/dns-message")
	request.Header.Set("Accept", "application/dns-message")
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("Accept-Encoding", "identity")
	if err := request.Write(connection); err != nil {
		return nil, err
	}
	// Bound headers as well as the DNS body; a small bufio buffer alone would
	// still allow an untrusted peer to allocate arbitrarily many HTTP headers.
	response, err := http.ReadResponse(bufio.NewReaderSize(io.LimitReader(connection, 3*maxDNSMessage), 4096), request)
	if err != nil {
		return nil, err
	}
	contentType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusOK || mediaErr != nil || contentType != "application/dns-message" || response.ContentLength > maxDNSMessage || response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity" {
		return nil, errors.New("invalid DoH status, framing or media type")
	}
	answer, err := io.ReadAll(io.LimitReader(response.Body, maxDNSMessage+1))
	// The request owns and closes the entire non-reused connection. Do not ask
	// Body.Close to drain an untrusted oversized/chunked response after this bound.
	if err != nil || len(answer) > maxDNSMessage {
		return nil, errors.New("DoH answer exceeded its bound")
	}
	return answer, nil
}
