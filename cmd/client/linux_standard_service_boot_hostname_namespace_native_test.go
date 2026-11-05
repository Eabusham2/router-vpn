//go:build linux && routervpn_controller_privileged

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/dnsmeasure"
)

const bootHostnameFixtureName = "node.transport-bootstrap.invalid"
const bootHostnameFixtureResolver = "198.19.0.53"

func init() {
	if len(os.Args) == 4 && os.Args[1] == "routervpn-boot-hostname-resolver" {
		if e := bootHostnameFixtureDNS(os.Args[2], os.Args[3]); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(93)
		}
		os.Exit(0)
	}
}
func bootHostnameFixtureDNS(answer, countFile string) error {
	ip := net.ParseIP(answer).To4()
	if ip == nil {
		return errors.New("fixture lost captured Node address")
	}
	conn, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(bootHostnameFixtureResolver), Port: 53})
	if e != nil {
		return e
	}
	defer conn.Close()
	fmt.Println("ready")
	count := 0
	for {
		buffer := make([]byte, 1024)
		n, remote, e := conn.ReadFromUDP(buffer)
		if e != nil {
			return e
		}
		query := buffer[:n]
		if len(query) < 4 {
			return errors.New("unexpected bootstrap datagram")
		}
		ipv6 := len(query) >= 4 && query[len(query)-3] == 28
		want, e := dnsmeasure.TransportBootstrapQuery(bootHostnameFixtureName, ipv6)
		if e != nil {
			return e
		}
		copy(want[:2], query[:2])
		if !bytes.Equal(query, want) {
			return errors.New("service asked an unrelated hostname or query")
		}
		reply := append([]byte(nil), query...)
		reply[2] = 0x81
		reply[3] = 0x80
		if !ipv6 {
			reply[7] = 1
			reply = append(reply, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4)
			reply = append(reply, ip...)
		}
		if _, e = conn.WriteToUDP(reply, remote); e != nil {
			return e
		}
		count++
		if e = os.WriteFile(countFile, []byte(strconv.Itoa(count)), 0600); e != nil {
			return e
		}
	}
}

// This fixture changes only the machine transport-bootstrap resolver in its
// private mount/net namespaces. Home AdGuard, its DNS transport, private Router
// target and encrypted Node credentials remain the ordinary public fixture.
func linuxHostTUNBootHostnameFixture(t *testing.T, peer *linuxHostTUNPeer) {
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
	if e = os.WriteFile(resolver, []byte("nameserver "+bootHostnameFixtureResolver+"\n"), 0600); e != nil {
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
	executable, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	countFile := filepath.Join(directory, "queries")
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
	dns := exec.CommandContext(ctx, "/usr/sbin/ip", "netns", "exec", "rvpn-peer", executable, "routervpn-boot-hostname-resolver", peer.address.Addr().String(), countFile)
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
		if e != nil || parse != nil || count < 2 {
			t.Error("public Node Connect omitted actual A/AAAA bootstrap", e, parse, count)
		}
		cancel()
		_ = dns.Wait()
	})
	if ready, e := bufio.NewReader(output).ReadString('\n'); e != nil || ready != "ready\n" {
		t.Fatal("captured bootstrap peer not ready", ready, e)
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
