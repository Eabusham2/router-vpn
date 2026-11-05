//go:build linux && routervpn_controller_privileged

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/dnsmeasure"
)

const bootHostnameFixtureName = "node.transport-bootstrap.invalid"
const bootHostnameFixtureResolver = "198.19.0.53"

func init() {
	if (len(os.Args) == 4 || len(os.Args) == 5) && os.Args[1] == "routervpn-boot-hostname-resolver" {
		mode := "udp"
		if len(os.Args) == 5 {
			mode = os.Args[4]
		}
		if e := bootHostnameFixtureDNS(os.Args[2], os.Args[3], mode); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(93)
		}
		os.Exit(0)
	}
}
func bootHostnameFixtureDNS(answer, countFile, mode string) error {
	ip := net.ParseIP(answer).To4()
	if ip == nil {
		return errors.New("fixture lost captured Node address")
	}
	var mu sync.Mutex
	count := 0
	reply := func(query []byte, truncated bool) ([]byte, error) {
		if len(query) < 12 {
			return nil, errors.New("short bootstrap question")
		}
		var original []byte
		ipv6 := false
		for _, six := range []bool{false, true} {
			want, e := dnsmeasure.TransportBootstrapQuery(bootHostnameFixtureName, six)
			if e != nil {
				return nil, e
			}
			copy(want[:2], query[:2])
			want[3] = query[3]
			if want[3]&^byte(0x20) != 0 {
				return nil, errors.New("unexpected bootstrap query flags")
			}
			base := append([]byte(nil), want...)
			if query[11] == 1 {
				want[11] = 1
				want = append(want, 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0)
			}
			if bytes.Equal(query, want) {
				original = base
				ipv6 = six
				break
			}
		}
		if original == nil {
			return nil, errors.New("service asked unrelated hostname/query")
		}
		mu.Lock()
		count++
		e := os.WriteFile(countFile, []byte(strconv.Itoa(count)), 0600)
		mu.Unlock()
		if e != nil {
			return nil, e
		}
		original[2] = 0x81
		original[3] = 0x80
		if truncated {
			original[2] |= 2
			return original, nil
		}
		if !ipv6 {
			original[7] = 1
			original = append(original, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4)
			original = append(original, ip...)
		}
		return original, nil
	}
	errorsOut := make(chan error, 2)
	if mode != "tcp" {
		conn, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(bootHostnameFixtureResolver), Port: 53})
		if e != nil {
			return e
		}
		defer conn.Close()
		go func() {
			for {
				buffer := make([]byte, 1024)
				n, remote, e := conn.ReadFromUDP(buffer)
				if e != nil {
					errorsOut <- e
					return
				}
				body, e := reply(buffer[:n], mode == "truncated")
				if e == nil {
					_, e = conn.WriteToUDP(body, remote)
				}
				if e != nil {
					errorsOut <- e
					return
				}
			}
		}()
	}
	if mode == "tcp" || mode == "truncated" {
		listener, e := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP(bootHostnameFixtureResolver), Port: 53})
		if e != nil {
			return e
		}
		defer listener.Close()
		go func() {
			for {
				conn, e := listener.AcceptTCP()
				if e != nil {
					errorsOut <- e
					return
				}
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				var size [2]byte
				_, e = io.ReadFull(conn, size[:])
				n := int(binary.BigEndian.Uint16(size[:]))
				if e == nil && (n < 17 || n > 278) {
					e = errors.New("unexpected original DNS TCP length")
				}
				var body []byte
				if e == nil {
					q := make([]byte, n)
					_, e = io.ReadFull(conn, q)
					if e == nil {
						body, e = reply(q, false)
					}
				}
				if e == nil {
					frame := make([]byte, len(body)+2)
					binary.BigEndian.PutUint16(frame, uint16(len(body)))
					copy(frame[2:], body)
					for len(frame) > 0 {
						var n int
						n, e = conn.Write(frame)
						if e != nil || n == 0 {
							break
						}
						frame = frame[n:]
					}
				}
				_ = conn.Close()
				if e != nil {
					errorsOut <- e
					return
				}
			}
		}()
	}
	fmt.Println("ready")
	return <-errorsOut
}

// This fixture changes only the machine transport-bootstrap resolver in its
// private mount/net namespaces. Home AdGuard, its DNS transport, private Router
// target and encrypted Node credentials remain the ordinary public fixture.
func linuxHostTUNBootHostnameFixture(t *testing.T, peer *linuxHostTUNPeer, scenario string) {
	mode := "udp"
	if scenario == "service-boot-hostname-tcp" {
		mode = "tcp"
	}
	if scenario == "service-boot-hostname-truncated" {
		mode = "truncated"
	}
	hostsOnly := scenario == "service-boot-hosts"
	t.Cleanup(func() { t.Logf("verified installed host captured resolver policy: %s", scenario) })
	t.Helper()
	directory, e := os.MkdirTemp("/opt", "boot-hostname-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	run := func(args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if output, e := exec.CommandContext(ctx, "/usr/sbin/ip", args...).CombinedOutput(); e != nil {
			t.Fatal(e, string(output))
		}
	}
	run("netns", "exec", "rvpn-peer", "ip", "addr", "add", bootHostnameFixtureResolver+"/32", "dev", "rvpn-peer")
	t.Cleanup(func() {
		run("netns", "exec", "rvpn-peer", "ip", "addr", "del", bootHostnameFixtureResolver+"/32", "dev", "rvpn-peer")
	})
	run("route", "add", bootHostnameFixtureResolver+"/32", "via", peer.address.Addr().String())
	t.Cleanup(func() { run("route", "del", bootHostnameFixtureResolver+"/32") })
	resolver := filepath.Join(directory, "resolv.conf")
	resolverBody := "nameserver " + bootHostnameFixtureResolver + "\noptions timeout:2 attempts:1\n"
	if mode == "tcp" {
		resolverBody += "options use-vc\n"
	}
	if hostsOnly {
		resolverBody = "nameserver 127.0.0.53\n"
	}
	for name, body := range map[string]string{"nsswitch.conf": "hosts: files dns\n", "hosts": ""} {
		if hostsOnly && name == "hosts" {
			body = peer.address.Addr().String() + " " + bootHostnameFixtureName + "\n"
		}
		source := filepath.Join(directory, name)
		if e = os.WriteFile(source, []byte(body), 0600); e != nil {
			t.Fatal(e)
		}
		target := filepath.Join("/etc", name)
		if e = syscall.Mount(source, target, "", syscall.MS_BIND, ""); e != nil {
			t.Fatal("private NSS/hosts bind", e)
		}
		t.Cleanup(func() {
			if e := syscall.Unmount(target, 0); e != nil {
				t.Error(e)
			}
		})
	}
	if e = os.WriteFile(resolver, []byte(resolverBody), 0600); e != nil {
		t.Fatal(e)
	}
	target := "/etc/resolv.conf"
	if info, e := os.Lstat(target); e != nil {
		t.Fatal(e)
	} else if info.Mode()&os.ModeSymlink != 0 {
		link, e := os.Readlink(target)
		if e != nil {
			t.Fatal(e)
		}
		if !filepath.IsAbs(link) {
			link = filepath.Join("/etc", link)
		}
		link = filepath.Clean(link)
		if !strings.HasPrefix(link, "/run/") {
			t.Fatal("fixture refuses to create an unrelated resolver target", link)
		}
		if e = os.MkdirAll(filepath.Dir(link), 0755); e != nil {
			t.Fatal(e)
		}
		if _, e = os.Stat(link); errors.Is(e, os.ErrNotExist) {
			if e = os.WriteFile(link, nil, 0600); e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() { os.Remove(link) })
		}
		target = link
	}
	if e = syscall.Mount(resolver, target, "", syscall.MS_BIND, ""); e != nil {
		t.Fatal("private resolver bind", e)
	}
	t.Cleanup(func() {
		if e := syscall.Unmount(target, 0); e != nil {
			t.Error(e)
		}
	})
	if !hostsOnly {
		executable, e := os.Executable()
		if e != nil {
			t.Fatal(e)
		}
		countFile := filepath.Join(directory, "queries")
		ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
		dns := exec.CommandContext(ctx, "/usr/sbin/ip", "netns", "exec", "rvpn-peer", executable, "routervpn-boot-hostname-resolver", peer.address.Addr().String(), countFile, mode)
		dns.Stderr = os.Stderr
		output, e := dns.StdoutPipe()
		if e != nil {
			cancel()
			t.Fatal(e)
		}
		if e = dns.Start(); e != nil {
			cancel()
			t.Fatal(e)
		}
		t.Cleanup(func() {
			body, e := os.ReadFile(countFile)
			count, parse := strconv.Atoi(string(body))
			minimum := 2
			if mode == "truncated" {
				minimum = 4
			}
			if e != nil || parse != nil || count < minimum {
				t.Error("public Node Connect omitted actual A/AAAA bootstrap", e, parse, count)
			}
			cancel()
			_ = dns.Wait()
		})
		if ready, e := bufio.NewReader(output).ReadString('\n'); e != nil || ready != "ready\n" {
			t.Fatal("captured bootstrap peer not ready", ready, e)
		}
	}
	profilePath := filepath.Join(linuxOwnedControllerRoot, "routers.json")
	body, e := os.ReadFile(profilePath)
	var store common.RouterProfileStore
	if e != nil || json.Unmarshal(body, &store) != nil || len(store.Profiles) != 1 {
		t.Fatal("hostname fixture lost selected profile", e)
	}
	p := &store.Profiles[0]
	if p.Endpoint != peer.address.Addr().String() || p.DNSMode != "home" || p.AdGuardIPv4 != "192.168.50.133" {
		t.Fatal("hostname fixture changed private targets")
	}
	p.Endpoint = bootHostnameFixtureName
	body, e = json.Marshal(store)
	if e != nil || os.WriteFile(profilePath, body, 0600) != nil {
		t.Fatal("hostname profile write", e)
	}
	asset := filepath.Join(linuxOwnedControllerRoot, "generated", p.ID, "shadowsocks", "sing-box.json")
	body, e = os.ReadFile(asset)
	if e != nil {
		t.Fatal(e)
	}
	old := []byte(`"server":"` + peer.address.Addr().String() + `"`)
	if bytes.Count(body, old) != 1 {
		t.Fatal("hostname fixture outer source is ambiguous")
	}
	body = bytes.Replace(body, old, []byte(`"server":"`+bootHostnameFixtureName+`"`), 1)
	if e = os.WriteFile(asset, body, 0600); e != nil {
		t.Fatal(e)
	}
}
