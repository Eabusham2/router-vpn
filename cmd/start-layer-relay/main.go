package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	whiteningLabel   = "router-vpn-xor-whitening-v1\x00"
	idleTimeout      = 2 * time.Minute
	maxKeyConfigSize = 4 << 20
)

type singBoxConfig struct {
	Inbounds  []singBoxEndpoint `json:"inbounds"`
	Outbounds []singBoxEndpoint `json:"outbounds"`
}

type singBoxEndpoint struct {
	Type     string `json:"type"`
	Method   string `json:"method"`
	Password string `json:"password"`
}

type relayConfig struct {
	mode      string
	listen    string
	target    string
	keyConfig string
}

type xorReader struct {
	r   io.Reader
	key [32]byte
	off uint64
}

func (x *xorReader) Read(p []byte) (int, error) {
	n, err := x.r.Read(p)
	for i := 0; i < n; i++ {
		p[i] ^= x.key[(x.off+uint64(i))%uint64(len(x.key))]
	}
	x.off += uint64(n)
	return n, err
}

type xorWriter struct {
	w   io.Writer
	key [32]byte
	off uint64
	buf []byte
}

func (x *xorWriter) Write(p []byte) (int, error) {
	if cap(x.buf) < len(p) {
		x.buf = make([]byte, len(p))
	}
	buf := x.buf[:len(p)]
	for i := range p {
		buf[i] = p[i] ^ x.key[(x.off+uint64(i))%uint64(len(x.key))]
	}
	n, err := x.w.Write(buf)
	x.off += uint64(n)
	return n, err
}

func readPrivateKeyConfig(path string) (singBoxConfig, error) {
	var cfg singBoxConfig
	path = strings.TrimSpace(path)
	if path == "" || strings.ContainsRune(path, '\x00') {
		return cfg, errors.New("private Shadowsocks key config path is missing or invalid")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return cfg, fmt.Errorf("lstat Shadowsocks config: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return cfg, errors.New("Shadowsocks key config must be a regular non-symlink file")
	}
	if before.Size() <= 0 || before.Size() > maxKeyConfigSize {
		return cfg, errors.New("Shadowsocks key config is empty or oversized")
	}
	if runtime.GOOS != "windows" && before.Mode().Perm()&0o077 != 0 {
		return cfg, fmt.Errorf("Shadowsocks key config permissions must be private, got %04o", before.Mode().Perm())
	}

	f, err := os.Open(path)
	if err != nil {
		return cfg, fmt.Errorf("open Shadowsocks config: %w", err)
	}
	opened, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return cfg, fmt.Errorf("stat opened Shadowsocks config: %w", err)
	}
	if !os.SameFile(before, opened) {
		_ = f.Close()
		return cfg, errors.New("Shadowsocks key config changed during open")
	}
	body, readErr := io.ReadAll(io.LimitReader(f, maxKeyConfigSize+1))
	closeErr := f.Close()
	if readErr != nil {
		return cfg, fmt.Errorf("read Shadowsocks config: %w", readErr)
	}
	if closeErr != nil {
		return cfg, fmt.Errorf("close Shadowsocks config: %w", closeErr)
	}
	if len(body) == 0 || len(body) > maxKeyConfigSize {
		return cfg, errors.New("Shadowsocks key config is empty or oversized")
	}
	final, err := os.Lstat(path)
	if err != nil {
		return cfg, fmt.Errorf("re-lstat Shadowsocks config: %w", err)
	}
	if final.Mode()&os.ModeSymlink != 0 || !final.Mode().IsRegular() || !os.SameFile(opened, final) {
		return cfg, errors.New("Shadowsocks key config changed during read")
	}
	if runtime.GOOS != "windows" && final.Mode().Perm()&0o077 != 0 {
		return cfg, errors.New("Shadowsocks key config permissions became non-private during read")
	}
	if err := json.Unmarshal(body, &cfg); err != nil {
		return cfg, fmt.Errorf("parse Shadowsocks config: %w", err)
	}
	return cfg, nil
}

func deriveKey(path string) ([32]byte, error) {
	var zero [32]byte
	cfg, err := readPrivateKeyConfig(path)
	if err != nil {
		return zero, err
	}
	var candidates []singBoxEndpoint
	for _, endpoint := range append(cfg.Inbounds, cfg.Outbounds...) {
		if strings.EqualFold(strings.TrimSpace(endpoint.Type), "shadowsocks") {
			candidates = append(candidates, endpoint)
		}
	}
	if len(candidates) != 1 {
		return zero, fmt.Errorf("expected exactly one Shadowsocks endpoint in key config, found %d", len(candidates))
	}
	ss := candidates[0]
	if strings.ToLower(strings.TrimSpace(ss.Method)) != "2022-blake3-aes-256-gcm" {
		return zero, fmt.Errorf("XOR whitening requires Shadowsocks 2022 AES-256-GCM, got %q", ss.Method)
	}
	if len(ss.Password) < 16 || strings.ContainsRune(ss.Password, '\x00') {
		return zero, errors.New("Shadowsocks password is missing or too short")
	}
	return sha256.Sum256([]byte(whiteningLabel + ss.Password)), nil
}

func abortPair(a, b net.Conn) {
	now := time.Now()
	_ = a.SetDeadline(now)
	_ = b.SetDeadline(now)
}

func closeWrite(conn net.Conn) {
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
		return
	}
	_ = conn.SetDeadline(time.Now())
}

func relayTCP(listen, target string, key [32]byte) error {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(in net.Conn) {
			defer in.Close()
			out, err := net.DialTimeout("tcp", target, 10*time.Second)
			if err != nil {
				return
			}
			defer out.Close()
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				if _, err := io.Copy(out, &xorReader{r: in, key: key}); err != nil {
					abortPair(in, out)
					return
				}
				closeWrite(out)
			}()
			go func() {
				defer wg.Done()
				if _, err := io.Copy(&xorWriter{w: in, key: key}, out); err != nil {
					abortPair(in, out)
					return
				}
				closeWrite(in)
			}()
			wg.Wait()
		}(conn)
	}
}

type udpSession struct {
	conn     *net.UDPConn
	peer     *net.UDPAddr
	lastUsed time.Time
}

func relayUDP(listen, target string, key [32]byte) error {
	listenAddr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return err
	}
	targetAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return err
	}
	ln, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		return err
	}
	defer ln.Close()

	var mu sync.Mutex
	sessions := make(map[string]*udpSession)
	closeSession := func(key string, session *udpSession) {
		mu.Lock()
		if sessions[key] == session {
			delete(sessions, key)
		}
		mu.Unlock()
		_ = session.conn.Close()
	}

	getSession := func(peer *net.UDPAddr) (*udpSession, error) {
		id := peer.String()
		mu.Lock()
		if session := sessions[id]; session != nil {
			session.lastUsed = time.Now()
			mu.Unlock()
			return session, nil
		}
		mu.Unlock()
		conn, err := net.DialUDP("udp", nil, targetAddr)
		if err != nil {
			return nil, err
		}
		session := &udpSession{conn: conn, peer: peer, lastUsed: time.Now()}
		mu.Lock()
		if existing := sessions[id]; existing != nil {
			mu.Unlock()
			_ = conn.Close()
			return existing, nil
		}
		sessions[id] = session
		mu.Unlock()
		go func(id string, session *udpSession) {
			buf := make([]byte, 65535)
			for {
				_ = session.conn.SetReadDeadline(time.Now().Add(idleTimeout))
				n, err := session.conn.Read(buf)
				if err != nil {
					closeSession(id, session)
					return
				}
				out := make([]byte, n)
				for i := 0; i < n; i++ {
					out[i] = buf[i] ^ key[i%len(key)]
				}
				if _, err := ln.WriteToUDP(out, session.peer); err != nil {
					closeSession(id, session)
					return
				}
				mu.Lock()
				if sessions[id] == session {
					session.lastUsed = time.Now()
				}
				mu.Unlock()
			}
		}(id, session)
		return session, nil
	}

	buf := make([]byte, 65535)
	for {
		n, peer, err := ln.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		session, err := getSession(peer)
		if err != nil {
			continue
		}
		out := make([]byte, n)
		for i := 0; i < n; i++ {
			out[i] = buf[i] ^ key[i%len(key)]
		}
		if _, err := session.conn.Write(out); err != nil {
			closeSession(peer.String(), session)
		}
	}
}

func run(cfg relayConfig) error {
	if cfg.mode != "client" && cfg.mode != "server" {
		return errors.New("mode must be client or server")
	}
	if strings.TrimSpace(cfg.listen) == "" || strings.TrimSpace(cfg.target) == "" {
		return errors.New("listen and target are required")
	}
	key, err := deriveKey(cfg.keyConfig)
	if err != nil {
		return err
	}
	errCh := make(chan error, 2)
	go func() { errCh <- relayTCP(cfg.listen, cfg.target, key) }()
	go func() { errCh <- relayUDP(cfg.listen, cfg.target, key) }()
	return <-errCh
}

func main() {
	var cfg relayConfig
	flag.StringVar(&cfg.mode, "mode", "", "client or server")
	flag.StringVar(&cfg.listen, "listen", "", "TCP+UDP listen address")
	flag.StringVar(&cfg.target, "target", "", "TCP+UDP upstream target")
	flag.StringVar(&cfg.keyConfig, "key-config", "", "private sing-box config containing one AES-256-GCM Shadowsocks endpoint")
	flag.Parse()
	if err := run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "start-layer relay:", err)
		os.Exit(1)
	}
}
