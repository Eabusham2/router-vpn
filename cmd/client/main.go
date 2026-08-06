package main

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"router-vpn/internal/common"
)

//go:embed ui.html
var uiFS embed.FS

type state struct {
	Connected bool   `json:"connected"`
	Mode      string `json:"mode"`
	DAITA     bool   `json:"daita"`
	Jumbo     bool   `json:"jumbo"`
	Socks     bool   `json:"socks"`
	LastError string `json:"last_error"`
}
type app struct {
	cfg   common.ClientConfig
	modes []common.Mode
	mu    sync.Mutex
	state state
	cmd   *exec.Cmd
}

func main() {
	path := getenv("HOMEVPN_CLIENT_CONFIG", "./client.json")
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	var c common.ClientConfig
	if err = json.Unmarshal(b, &c); err != nil {
		log.Fatal(err)
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8788"
	}
	if c.AutoTestSeconds == 0 {
		c.AutoTestSeconds = 8
	}
	mb, err := os.ReadFile(c.ModesFile)
	if err != nil {
		log.Fatal(err)
	}
	var modes []common.Mode
	if err = json.Unmarshal(mb, &modes); err != nil {
		log.Fatal(err)
	}
	a := &app{cfg: c, modes: modes, state: state{Mode: "off"}}
	h := http.NewServeMux()
	h.HandleFunc("/", a.index)
	h.HandleFunc("/api/status", a.status)
	h.HandleFunc("/api/modes", a.listModes)
	h.HandleFunc("/api/info", a.info)
	h.HandleFunc("/api/connect", a.connect)
	h.HandleFunc("/api/disconnect", a.disconnect)
	h.HandleFunc("/api/auto", a.auto)
	h.HandleFunc("/api/options", a.options)
	h.HandleFunc("/api/forward", a.forward)
	h.HandleFunc("/api/forward/clear", a.clearForward)
	log.Printf("Router VPN client UI: http://%s", c.Listen)
	log.Fatal(http.ListenAndServe(c.Listen, h))
}
func getenv(k, v string) string {
	if x := os.Getenv(k); x != "" {
		return x
	}
	return v
}
func (a *app) index(w http.ResponseWriter, r *http.Request) {
	b, _ := uiFS.ReadFile("ui.html")
	w.Header().Set("content-type", "text/html; charset=utf-8")
	w.Write(b)
}
func (a *app) status(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	json.NewEncoder(w).Encode(a.state)
}

func (a *app) info(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]any{
		"adguard_ipv4":   a.cfg.AdGuardIPv4,
		"adguard_ipv6":   a.cfg.AdGuardIPv6,
		"socks_host":     a.cfg.SocksHost,
		"socks_port":     a.cfg.SocksPort,
		"socks_username": a.cfg.SocksUsername,
		"socks_password": a.cfg.SocksPassword,
	})
}

func (a *app) listModes(w http.ResponseWriter, r *http.Request) {
	out := make([]common.ModeStatus, 0, len(a.modes))
	for _, m := range a.modes {
		ok, reason := a.checkMode(m)
		out = append(out, common.ModeStatus{Mode: m, Available: ok, Reason: reason})
	}
	json.NewEncoder(w).Encode(out)
}

func (a *app) checkMode(m common.Mode) (bool, string) {
	if len(m.CheckCommand) == 0 {
		return true, ""
	}
	cmd := exec.Command(m.CheckCommand[0], m.CheckCommand[1:]...)
	cmd.Dir = a.cfg.ScriptsDir
	cmd.Env = append(os.Environ(), "HOMEVPN_ROOT="+filepath.Clean(getenv("HOMEVPN_ROOT", "/opt/router-vpn-client")))
	out, err := cmd.CombinedOutput()
	if err != nil {
		reason := strings.TrimSpace(string(out))
		if reason == "" {
			reason = err.Error()
		}
		return false, reason
	}
	return true, strings.TrimSpace(string(out))
}
func (a *app) mode(id string) (common.Mode, error) {
	for _, m := range a.modes {
		if m.ID == id {
			return m, nil
		}
	}
	return common.Mode{}, errors.New("unknown mode")
}
func (a *app) connect(w http.ResponseWriter, r *http.Request) {
	var q struct {
		Mode string `json:"mode"`
	}
	if json.NewDecoder(r.Body).Decode(&q) != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if err := a.startMode(q.Mode); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Fprint(w, `{"ok":true}`)
}
func (a *app) disconnect(w http.ResponseWriter, r *http.Request) {
	if err := a.stopMode(); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Fprint(w, `{"ok":true}`)
}
func (a *app) options(w http.ResponseWriter, r *http.Request) {
	var q struct {
		DAITA *bool `json:"daita"`
		Jumbo *bool `json:"jumbo"`
		Socks *bool `json:"socks"`
	}
	if json.NewDecoder(r.Body).Decode(&q) != nil {
		http.Error(w, "bad json", 400)
		return
	}
	a.mu.Lock()
	if q.DAITA != nil {
		a.state.DAITA = *q.DAITA
	}
	if q.Jumbo != nil {
		a.state.Jumbo = *q.Jumbo
	}
	if q.Socks != nil {
		a.state.Socks = *q.Socks
	}
	a.mu.Unlock()
	fmt.Fprint(w, `{"ok":true}`)
}
func (a *app) startMode(id string) error {
	m, err := a.mode(id)
	if err != nil {
		return err
	}
	if ok, reason := a.checkMode(m); !ok {
		return fmt.Errorf("mode unavailable: %s", reason)
	}
	a.mu.Lock()
	daita, jumbo := a.state.DAITA, a.state.Jumbo
	a.mu.Unlock()
	if daita && !m.DAITASupported {
		return errors.New("DAITA is not available for this mode")
	}
	if jumbo && !m.JumboSupported {
		return errors.New("Jumbo TUN is not available for this mode; leave it off for WireGuard/AWG")
	}
	if err = a.stopMode(); err != nil {
		return err
	}
	a.mu.Lock()
	env := append(os.Environ(), fmt.Sprintf("HOMEVPN_DAITA=%t", a.state.DAITA), fmt.Sprintf("HOMEVPN_JUMBO=%t", a.state.Jumbo), fmt.Sprintf("HOMEVPN_SOCKS=%t", a.state.Socks), fmt.Sprintf("HOMEVPN_MTU=%d", m.MTU), "HOMEVPN_ADGUARD4="+a.cfg.AdGuardIPv4, "HOMEVPN_ADGUARD6="+a.cfg.AdGuardIPv6)
	a.mu.Unlock()
	if len(m.Command) == 0 {
		return errors.New("mode has no command")
	}
	cmd := exec.Command(m.Command[0], m.Command[1:]...)
	cmd.Env = env
	cmd.Dir = a.cfg.ScriptsDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	a.mu.Lock()
	a.cmd = cmd
	a.state.Connected = true
	a.state.Mode = id
	a.state.LastError = ""
	a.mu.Unlock()
	time.Sleep(1200 * time.Millisecond)
	return nil
}
func (a *app) stopMode() error {
	a.mu.Lock()
	cmd := a.cmd
	modeID := a.state.Mode
	a.cmd = nil
	a.state.Connected = false
	a.state.Mode = "off"
	a.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = cmd.Process.Kill()
		}
	}
	if modeID != "off" {
		if m, err := a.mode(modeID); err == nil && len(m.StopCommand) > 0 {
			c := exec.Command(m.StopCommand[0], m.StopCommand[1:]...)
			c.Dir = a.cfg.ScriptsDir
			_ = c.Run()
		}
	}
	return nil
}
func (a *app) auto(w http.ResponseWriter, r *http.Request) {
	type result struct {
		Mode    string
		Latency time.Duration
	}
	var ok []result
	for _, m := range a.modes {
		if !m.AutoEligible {
			continue
		}
		if err := a.startMode(m.ID); err != nil {
			continue
		}
		lat, err := a.testHealth()
		_ = a.stopMode()
		if err == nil {
			ok = append(ok, result{m.ID, lat})
		}
	}
	if len(ok) == 0 {
		http.Error(w, "no working mode", 503)
		return
	}
	sort.Slice(ok, func(i, j int) bool { return ok[i].Latency < ok[j].Latency })
	if err := a.startMode(ok[0].Mode); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "mode": ok[0].Mode, "latency_ms": float64(ok[0].Latency.Microseconds()) / 1000})
}
func (a *app) testHealth() (time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(a.cfg.AutoTestSeconds)*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", a.cfg.HealthURL, nil)
	t := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode/100 != 2 {
		return 0, fmt.Errorf("health %s", resp.Status)
	}
	return time.Since(t), nil
}
func (a *app) forward(w http.ResponseWriter, r *http.Request) { proxyJSON(a, w, r, "/api/forward") }
func (a *app) clearForward(w http.ResponseWriter, r *http.Request) {
	proxyJSON(a, w, r, "/api/forward/clear")
}
func proxyJSON(a *app, w http.ResponseWriter, r *http.Request, path string) {
	body, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
	req, err := http.NewRequest("POST", strings.TrimRight(a.cfg.RouterAPI, "/")+path, bytes.NewReader(body))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	req.Header.Set("Authorization", "Bearer "+a.cfg.APIToken)
	req.Header.Set("content-type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	defer resp.Body.Close()
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

var _ = filepath.Separator
