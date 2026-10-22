package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func viaEntryBaseFixture(t *testing.T, mode string) (common.RouterProfile, map[string][]byte) {
	t.Helper()
	entry, files := desktopNodeFixture(t, "198.51.100.8")
	full, split := "wg.conf", "wg-socks.conf"
	if mode != "wg" {
		junk := 3
		if mode == "awg2-strong" {
			junk = 8
		}
		parameters := fmt.Sprintf("[Interface]\nJc = %d\nJmin = 40\nJmax = 900\nS1 = 56\nS2 = 48\nS3 = 24\nS4 = 32\nH1 = 10000000-19999999\nH2 = 20000000-29999999\nH3 = 30000000-39999999\nH4 = 40000000-49999999", junk)
		files = map[string][]byte{"awg.conf": []byte(strings.Replace(string(files["wg.conf"]), "[Interface]", parameters, 1))}
		full, split = "awg.conf", "awg-socks.conf"
	}
	files[split] = []byte(strings.ReplaceAll(string(files[full]), "0.0.0.0/0, ::/0", "10.77.0.0/24"))
	return entry, files
}

func TestViaEntryCompilerPreservesCapturedTransportAndPolicyWithoutSystemTUN(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, layer := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				entry, files := viaEntryBaseFixture(t, mode)
				entry.StartLayer, entry.IPv6Mode, entry.HomeLANAccess = layer, "off", false
				entry.DNSMode, entry.DNSProtocol, entry.DNSHost, entry.DNSPort, entry.DNSServerName = "custom", "https", "resolver.example.test", 8443, "resolver-certificate.example.test"
				entry.MTUPolicy, entry.ManualMTU = "manual", 1392
				var start map[string][]byte
				if layer != "off" {
					start = map[string][]byte{"sing-box.json": []byte(fmt.Sprintf(`{"outbounds":[{"type":"shadowsocks","tag":"proxy","method":"2022-blake3-aes-256-gcm","password":%q,"server":"198.51.100.8","server_port":8388}]}`, base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))))}
				}
				baseline, _, err := compileDesktopNode(context.Background(), entry, mode, files, start, nil)
				if err != nil {
					t.Fatal(err)
				}
				candidates := []common.RouterProfile{{ID: "exit-a", Endpoint: "candidate.invalid"}, {ID: "exit-b", Endpoint: "198.51.100.22"}}
				data, allowed, err := compileViaEntryLane(context.Background(), entry, mode, files, start, candidates, 27123, "private-user", "private-password")
				if err != nil {
					t.Fatal(err)
				}
				var before, after map[string]any
				_ = json.Unmarshal([]byte(baseline.Config()), &before)
				_ = json.Unmarshal(data, &after)
				for _, field := range []string{"endpoints", "outbounds", "dns", "services"} {
					if !reflect.DeepEqual(before[field], after[field]) {
						t.Fatal("candidate adapter changed captured credentials, Start Layer, DNS or performance policy", field)
					}
				}
				input := after["inbounds"].([]any)[0].(map[string]any)
				if input["type"] != "socks" || input["listen"] != "127.0.0.1" || input["listen_port"] != float64(27123) || input["auto_route"] != nil || input["strict_route"] != nil || len(input["users"].([]any)) != 1 {
					t.Fatal("candidate lane is not an authenticated private userspace input")
				}
				if !allowed["candidate.invalid:443"] || !allowed["10.77.0.1:8787"] || allowed["other.invalid:443"] || allowed["candidate.invalid:22"] {
					t.Fatal("candidate socket allowlist escaped exact captured destinations")
				}
				rules := after["route"].(map[string]any)["rules"].([]any)
				if rules[0].(map[string]any)["ip_version"] != float64(6) || rules[1].(map[string]any)["outbound"] != "proxy" || rules[len(rules)-1].(map[string]any)["action"] != "reject" {
					t.Fatal("IPv6, private proof exception, or final deny is missing")
				}
				for _, raw := range rules {
					if raw.(map[string]any)["action"] == "sniff" {
						t.Fatal("sniffing may prematurely acknowledge a lazy SOCKS input")
					}
				}
				if binary := os.Getenv("ROUTERVPN_VIA_ENTRY_NATIVE_CLI"); binary != "" {
					directory := t.TempDir()
					path := filepath.Join(directory, "candidate.json")
					if err := os.WriteFile(path, data, 0600); err != nil {
						t.Fatal(err)
					}
					command := exec.Command(binary, "check", "-c", path, "-D", directory)
					command.Env = nativeLibraryEnvironment(os.Environ(), filepath.Dir(binary))
					if output, err := command.CombinedOutput(); err != nil {
						t.Fatalf("actual pinned native compiler rejected the captured lane: %v: %s", err, output)
					}
				}
			})
		}
	}
}

func readViaEntrySOCKSRequest(conn net.Conn, username, password string) (string, error) {
	bad := errors.New("fixture received an unowned SOCKS request")
	reader := bufio.NewReader(conn)
	var first [3]byte
	if _, err := io.ReadFull(reader, first[:]); err != nil || first != [3]byte{5, 1, 2} {
		return "", bad
	}
	if _, err := conn.Write([]byte{5, 2}); err != nil {
		return "", err
	}
	var pair [2]byte
	if _, err := io.ReadFull(reader, pair[:]); err != nil || pair[0] != 1 || pair[1] == 0 {
		return "", bad
	}
	user := make([]byte, int(pair[1]))
	if _, err := io.ReadFull(reader, user); err != nil {
		return "", err
	}
	length, err := reader.ReadByte()
	if err != nil || length == 0 {
		return "", bad
	}
	pass := make([]byte, int(length))
	if _, err := io.ReadFull(reader, pass); err != nil || string(user) != username || string(pass) != password {
		_, _ = conn.Write([]byte{1, 1})
		return "", bad
	}
	if _, err := conn.Write([]byte{1, 0}); err != nil {
		return "", err
	}
	var request [4]byte
	if _, err := io.ReadFull(reader, request[:]); err != nil || request[0] != 5 || request[1] != 1 || request[2] != 0 {
		return "", bad
	}
	size := 0
	switch request[3] {
	case 1:
		size = 4
	case 4:
		size = 16
	case 3:
		length, err := reader.ReadByte()
		if err != nil || length == 0 {
			return "", bad
		}
		size = int(length)
	default:
		return "", bad
	}
	host := make([]byte, size)
	if _, err := io.ReadFull(reader, host); err != nil {
		return "", err
	}
	if _, err := io.ReadFull(reader, pair[:]); err != nil {
		return "", err
	}
	name := string(host)
	if request[3] != 3 {
		name = net.IP(host).String()
	}
	return net.JoinHostPort(name, strconv.Itoa(int(binary.BigEndian.Uint16(pair[:])))), nil
}

func TestViaEntrySOCKSWaitsForCompleteUpstreamSuccess(t *testing.T) {
	for _, response := range []string{"success", "refused", "truncated"} {
		t.Run(response, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			_ = client.SetDeadline(time.Now().Add(2 * time.Second))
			arrived := make(chan string, 1)
			release := make(chan struct{})
			go func() {
				defer server.Close()
				address, err := readViaEntrySOCKSRequest(server, "captured-user", "captured-password")
				if err != nil {
					arrived <- err.Error()
					return
				}
				arrived <- address
				<-release
				reply := []byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}
				if response == "refused" {
					reply[1] = 5
				} else if response == "truncated" {
					reply = reply[:4]
				}
				_, _ = server.Write(reply)
			}()
			done := make(chan error, 1)
			go func() {
				done <- viaEntrySOCKSHandshake(client, "unresolvable-candidate.invalid:443", "captured-user", "captured-password")
			}()
			if address := <-arrived; address != "unresolvable-candidate.invalid:443" {
				t.Fatal("candidate was resolved or changed outside its lane", address)
			}
			select {
			case err := <-done:
				t.Fatal("proxy greeting was mistaken for routed upstream success", err)
			case <-time.After(40 * time.Millisecond):
			}
			close(release)
			err := <-done
			if (response == "success") != (err == nil) {
				t.Fatal("upstream refusal or truncated reply became a sample", response, err)
			}
		})
	}
}

func TestViaEntrySOCKSRejectsAuthenticationDowngrade(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		var hello [3]byte
		_, _ = io.ReadFull(server, hello[:])
		_, _ = server.Write([]byte{5, 0})
	}()
	if err := viaEntrySOCKSHandshake(client, "candidate.invalid:443", "captured", "secret"); err == nil {
		t.Fatal("unauthenticated foreign listener was accepted")
	}
}

func TestViaEntryProcessFixture(t *testing.T) {
	if os.Getenv("ROUTERVPN_VIA_ENTRY_PROCESS_FIXTURE") == "1" {
		for {
			time.Sleep(time.Second)
		}
	}
}

func TestViaEntryNativeCloseJoinsExactProcessAndRetainsChangedDirectory(t *testing.T) {
	root := desktopAWGPrivateTestRoot(t)
	directory, err := newPrivateRuntimeDir(root, "via-entry-candidates")
	if err != nil {
		t.Fatal(err)
	}
	info, err := captureViaEntryDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	command := exec.Command(os.Args[0], "-test.run=^TestViaEntryProcessFixture$")
	command.Env = append(os.Environ(), "ROUTERVPN_VIA_ENTRY_PROCESS_FIXTURE=1")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = command.Wait(); close(done) }()
	lane := &viaEntryNativeLane{ctx: ctx, cancel: cancel, command: command, processDone: done, directory: directory, directoryInfo: info, conns: map[*viaEntryNativeConn]bool{}}
	retired := directory + "-original"
	if err := os.Rename(directory, retired); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	stop, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	if err := lane.Close(stop); err == nil {
		t.Fatal("changed private directory was deleted or forgotten")
	}
	select {
	case <-done:
	default:
		t.Fatal("process identity was released before Wait joined")
	}
	if _, err := os.Stat(directory); err != nil {
		t.Fatal("replacement directory was touched")
	}
	if err := os.Remove(directory); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(retired, directory); err != nil {
		t.Fatal(err)
	}
	if err := lane.Close(stop); err != nil || !lane.removed {
		t.Fatal("same-directory cleanup retry failed", err)
	}
	if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("owned private source was not retired")
	}
}

func TestViaEntryFailedLaunchDoesNotDeleteReplacementDirectory(t *testing.T) {
	root := desktopAWGPrivateTestRoot(t)
	lane, err := launchViaEntryNativeLane(context.Background(), root, filepath.Join(root, "missing-native-binary"), []byte(`{"fixture":true}`), 27123, "private-user", "private-password", nil)
	if err == nil || lane == nil {
		t.Fatal("failed process start forgot its staged source owner")
	}
	owned := lane.(*viaEntryNativeLane)
	directory, retired := owned.directory, owned.directory+"-original"
	if err := os.Rename(directory, retired); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(directory, "foreign.txt")
	if err := os.WriteFile(foreign, []byte("replacement owner"), 0600); err != nil {
		t.Fatal(err)
	}
	stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := lane.Close(stop); err == nil || owned.removed {
		t.Fatal("failed launch retired a different directory at the same path")
	}
	if body, err := os.ReadFile(foreign); err != nil || string(body) != "replacement owner" {
		t.Fatal("replacement contents changed", err)
	}
	if _, err := os.Stat(filepath.Join(retired, "sing-box.json")); err != nil {
		t.Fatal("original launch source was forgotten before confirmed cleanup", err)
	}
	if err := os.Remove(foreign); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(directory); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(retired, directory); err != nil {
		t.Fatal(err)
	}
	if err := lane.Close(stop); err != nil || !owned.removed {
		t.Fatal("restored original source could not be retired", err)
	}
}

func TestViaEntryPinnedNativeUpstreamResponseAndCancellation(t *testing.T) {
	binary := os.Getenv("ROUTERVPN_VIA_ENTRY_NATIVE_CLI")
	if binary == "" {
		t.Skip("exact pinned native CLI supplied by desktop native runtime workflow")
	}
	// A real native SOCKS input/route/outbound sits between the controller and
	// an isolated upstream fixture. Its delayed remote CONNECT reply must delay
	// the controller sample; an early native HTTP CONNECT acknowledgement would
	// fail this regression. The synthetic upstream maps only captured fixture
	// names to a real local responder and never contacts the Internet.
	upstream, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	responder, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer responder.Close()
	var workers sync.WaitGroup
	var sockets sync.Map
	blocked := make(chan struct{})
	var blockedOnce sync.Once
	go func() {
		for {
			conn, err := responder.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		for {
			conn, err := upstream.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			sockets.Store(conn, true)
			go func() {
				defer workers.Done()
				defer conn.Close()
				defer sockets.Delete(conn)
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				address, err := readViaEntrySOCKSRequest(conn, "upstream-user", "upstream-password")
				if err != nil {
					return
				}
				host, _, _ := net.SplitHostPort(address)
				if host == "blocked.invalid" {
					blockedOnce.Do(func() { close(blocked) })
					_, _ = io.Copy(io.Discard, conn)
					return
				}
				if host != "measured.invalid" {
					_, _ = conn.Write([]byte{5, 5, 0, 1, 127, 0, 0, 1, 0, 0})
					return
				}
				time.Sleep(75 * time.Millisecond)
				remote, err := net.DialTimeout("tcp", responder.Addr().String(), time.Second)
				if err != nil {
					return
				}
				_ = remote.Close()
				_, _ = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				_, _ = io.Copy(io.Discard, conn)
			}()
		}
	}()
	defer func() {
		_ = upstream.Close()
		<-accepted
		sockets.Range(func(key, _ any) bool { _ = key.(net.Conn).Close(); return true })
		workers.Wait()
	}()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	config := map[string]any{
		"log":       map[string]any{"disabled": true},
		"inbounds":  []any{map[string]any{"type": "socks", "tag": "captured-input", "listen": "127.0.0.1", "listen_port": port, "users": []any{map[string]any{"username": "local-user", "password": "local-password"}}}},
		"outbounds": []any{map[string]any{"type": "socks", "tag": "captured-entry", "server": "127.0.0.1", "server_port": upstream.Addr().(*net.TCPAddr).Port, "version": "5", "username": "upstream-user", "password": "upstream-password"}},
		"route":     map[string]any{"final": "captured-entry"},
	}
	data, _ := json.Marshal(config)
	allowed := map[string]bool{"blocked.invalid:443": true}
	for _, host := range []string{"measured.invalid", "refused.invalid"} {
		for _, port := range viaEntryProbePorts {
			allowed[net.JoinHostPort(host, strconv.Itoa(port))] = true
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lane, err := launchViaEntryNativeLane(ctx, desktopAWGPrivateTestRoot(t), binary, data, port, "local-user", "local-password", allowed)
	if lane != nil {
		defer func() {
			stop, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := lane.Close(stop); err != nil {
				t.Error(err)
			}
		}()
	}
	if err != nil {
		t.Fatal("pinned native process failed", err)
	}
	result, err := measureViaEntryCandidate(ctx, lane, common.RouterProfile{ID: "captured", Endpoint: "measured.invalid"}, 3)
	if err != nil || !eligibleViaEntryResult(result) || result.MedianMs < 70 {
		t.Fatal("native upstream delay was replaced by local acknowledgement timing", result, err)
	}
	if _, err := measureViaEntryCandidate(ctx, lane, common.RouterProfile{ID: "refused", Endpoint: "refused.invalid"}, 3); err == nil {
		t.Fatal("native upstream refusal became a latency sample")
	}
	if conn, err := lane.DialContext(ctx, "tcp", "uncaptured.invalid:443"); err == nil || conn != nil {
		t.Fatal("uncaptured target escaped the private adapter allowlist")
	}
	request, requestCancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		conn, err := lane.DialContext(request, "tcp", "blocked.invalid:443")
		if conn != nil {
			_ = conn.Close()
		}
		done <- err
	}()
	select {
	case <-blocked:
	case <-time.After(2 * time.Second):
		t.Fatal("native blocked upstream was not reached")
	}
	requestCancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled native handshake adopted")
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not close owned native socket")
	}
	stop, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer stopCancel()
	if err := lane.Close(stop); err != nil || lane.Alive() {
		t.Fatal("native process and sockets did not drain", err)
	}
}
