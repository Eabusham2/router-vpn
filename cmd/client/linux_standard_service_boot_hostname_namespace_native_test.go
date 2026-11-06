//go:build linux && routervpn_controller_privileged

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
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
	"router-vpn/internal/standardengine"
	"router-vpn/internal/systembootstrap"
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
	countTLS := 0
	reply := func(query []byte, truncated bool) ([]byte, error) {
		if len(query) < 12 {
			return nil, errors.New("short bootstrap question")
		}
		if mode == "dnssec-cname" || mode == "dnssec-dname" {
			body, target, proof, err := bootHostnameAliasDNSReply(query, mode, ip)
			if err != nil {
				return nil, err
			}
			mu.Lock()
			count++
			err = os.WriteFile(countFile, []byte(strconv.Itoa(count)), 0600)
			if err == nil && target {
				err = bootHostnameAliasCount(countFile + ".alias-target")
			}
			if err == nil && proof {
				err = bootHostnameAliasCount(countFile + ".alias-proof")
			}
			mu.Unlock()
			return body, err
		}
		var original []byte
		ipv6 := false
		if mode != "dnssec-nta" {
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
		}
		if mode == "dnssec-nta" {
			for _, kind := range []uint16{1, 28} {
				if _, err := standardengine.ResolvedDNSSECQuestionFromWire(bootHostnameFixtureName, kind, query); err == nil {
					original, _ = dnsmeasure.TransportBootstrapQuery(bootHostnameFixtureName, kind == 28)
					copy(original[:2], query[:2])
					ipv6 = kind == 28
					break
				}
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
	if mode == "parallel" {
		return bootHostnameParallelDNS(reply, countFile)
	}
	errorsOut := make(chan error, 2)
	if mode != "tcp" && mode != "opportunistic-tls" {
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
	if mode == "tcp" || mode == "truncated" || mode == "opportunistic-tls" || mode == "opportunistic-fallback" {
		listener, e := net.Listen("tcp4", net.JoinHostPort(bootHostnameFixtureResolver, "53"))
		if e != nil {
			return e
		}
		if mode == "opportunistic-tls" {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return err
			}
			certificate := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"fixture.untrusted.invalid"}}
			raw, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
			if err != nil {
				return err
			}
			listener = tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{raw}, PrivateKey: key}}})
		}
		defer listener.Close()
		go func() {
			for {
				conn, e := listener.Accept()
				if e != nil {
					errorsOut <- e
					return
				}
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

				if mode == "opportunistic-fallback" {
					var header [5]byte
					_, e = io.ReadFull(conn, header[:])
					if e == nil && (header[0] != 22 || header[1] != 3) {
						e = errors.New("opportunistic plaintext skipped original TLS attempt")
					}
					if e == nil {
						mu.Lock()
						countTLS++
						e = os.WriteFile(countFile+".tls", []byte(strconv.Itoa(countTLS)), 0600)
						mu.Unlock()
					}
					if e == nil {
						_, e = conn.Write([]byte("plain"))
					}
					conn.Close()
					if e != nil {
						errorsOut <- e
						return
					}
					continue
				}
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
	if scenario == "service-boot-hostname-tcp" || scenario == "service-boot-resolved-tcp" {
		mode = "tcp"
	}
	if scenario == "service-boot-hostname-truncated" {
		mode = "truncated"
	}
	if scenario == "service-boot-resolved-parallel" {
		mode = "parallel"
	}
	if scenario == "service-boot-resolved-opportunistic-tls" {
		mode = "opportunistic-tls"
	}
	if scenario == "service-boot-resolved-opportunistic-fallback" {
		mode = "opportunistic-fallback"
	}
	if strings.HasPrefix(scenario, "service-boot-resolved-dnssec-") {
		mode = strings.TrimPrefix(scenario, "service-boot-resolved-")
	}
	hostsOnly := scenario == "service-boot-hosts"
	resolved := linuxHostTUNResolvedCase(scenario)
	localResolved := scenario == "service-boot-resolved-local"
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
	if hostsOnly || resolved {
		resolverBody = "nameserver 127.0.0.53\noptions timeout:2 attempts:1\n"
		if mode == "tcp" {
			resolverBody += "options use-vc\n"
		}
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
	if !hostsOnly && !localResolved {
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
			if mode == "truncated" || mode == "parallel" {
				minimum = 4
			}
			if e != nil || parse != nil || count < minimum {
				t.Error("public Node Connect omitted actual A/AAAA bootstrap", e, parse, count)
			}
			if mode == "dnssec-cname" || mode == "dnssec-dname" {
				for _, suffix := range []string{".alias-target", ".alias-proof"} {
					raw, err := os.ReadFile(countFile + suffix)
					n, parse := strconv.Atoi(string(raw))
					if err != nil || parse != nil || n < 2 {
						t.Error("alias omitted real target or typed proof queries", suffix, err, parse, n)
					}
				}
				t.Logf("verified installed DNSSEC alias original proof and target wire queries: %s", scenario)
			}
			if mode == "opportunistic-fallback" {
				b, err := os.ReadFile(countFile + ".tls")
				n, parse := strconv.Atoi(string(b))
				if err != nil || parse != nil || n < 2 {
					t.Error("original opportunistic TLS attempts omitted", err, parse, n)
				}
			}
			if mode == "parallel" {
				b, err := os.ReadFile(countFile + ".parallel")
				n, parse := strconv.Atoi(string(b))
				if err != nil || parse != nil || n < 2 {
					t.Error("independent physical DNS scopes missed barrier", err, parse, n)
				}
			}
			cancel()
			_ = dns.Wait()
		})
		if ready, e := bufio.NewReader(output).ReadString('\n'); e != nil || ready != "ready\n" {
			t.Fatal("captured bootstrap peer not ready", ready, e)
		}
	}
	if resolved {
		linuxHostTUNResolvedBroker(t, peer, scenario)
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

// Each socket must receive the same original question before either scope may
// answer. The global scope returns NXDOMAIN first; the independent link scope
// then returns the usable answer. Serial scope imitation cannot pass this gate.
func bootHostnameParallelDNS(reply func([]byte, bool) ([]byte, error), countFile string) error {
	type pair struct {
		seen         map[int]bool
		arrived      chan struct{}
		negativeSent chan struct{}
	}
	var mu sync.Mutex
	pairs := map[string]*pair{}
	completed := 0
	errorsOut := make(chan error, 2)
	for _, port := range []int{53, 2053} {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(bootHostnameFixtureResolver), Port: port})
		if err != nil {
			return err
		}
		defer conn.Close()
		go func(port int, conn *net.UDPConn) {
			for {
				buffer := make([]byte, 1024)
				n, remote, err := conn.ReadFromUDP(buffer)
				if err != nil {
					errorsOut <- err
					return
				}
				query := buffer[:n]
				mu.Lock()
				key := string(query)
				p := pairs[key]
				if p == nil {
					p = &pair{seen: map[int]bool{}, arrived: make(chan struct{}), negativeSent: make(chan struct{})}
					pairs[key] = p
				}
				if p.seen[port] {
					mu.Unlock()
					errorsOut <- errors.New("duplicate original scope query")
					return
				}
				p.seen[port] = true
				if len(p.seen) == 2 {
					close(p.arrived)
				}
				mu.Unlock()
				select {
				case <-p.arrived:
				case <-time.After(3 * time.Second):
					errorsOut <- errors.New("equal-best resolver scopes were serialized")
					return
				}
				answer, err := reply(query, false)
				if err != nil {
					errorsOut <- err
					return
				}
				if port == 53 {
					answer = append([]byte(nil), query...)
					answer[2] = 0x81
					answer[3] = 0x83
				} else {
					select {
					case <-p.negativeSent:
					case <-time.After(3 * time.Second):
						errorsOut <- errors.New("global negative omitted")
						return
					}
				}
				if _, err = conn.WriteToUDP(answer, remote); err != nil {
					errorsOut <- err
					return
				}
				if port == 53 {
					close(p.negativeSent)
				} else {
					mu.Lock()
					completed++
					err = os.WriteFile(countFile+".parallel", []byte(strconv.Itoa(completed)), 0600)
					mu.Unlock()
					if err != nil {
						errorsOut <- err
						return
					}
				}
			}
		}(port, conn)
	}
	fmt.Println("ready")
	return <-errorsOut
}

const bootHostnameAliasTarget = "node.alias-bootstrap.invalid"

func bootHostnameAliasCount(path string) error {
	old, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	n := 0
	if err == nil {
		n, err = strconv.Atoi(string(old))
		if err != nil {
			return err
		}
	}
	return os.WriteFile(path, []byte(strconv.Itoa(n+1)), 0600)
}
func bootHostnameAliasName(name string) []byte {
	var wire []byte
	for _, label := range strings.Split(name, ".") {
		wire = append(wire, byte(len(label)))
		wire = append(wire, label...)
	}
	return append(wire, 0)
}

// These unsigned NTA fixtures deliberately send AD. Only the original local
// validator may establish trust; the upstream's AD bit is never authority.
func bootHostnameAliasDNSReply(query []byte, mode string, ip net.IP) ([]byte, bool, bool, error) {
	name := ""
	kind := uint16(0)
	for _, candidate := range []string{bootHostnameFixtureName, bootHostnameAliasTarget} {
		for _, typ := range []uint16{1, 28, 5} {
			if typ == 5 && candidate != bootHostnameFixtureName {
				continue
			}
			_, err := standardengine.ResolvedDNSSECQuestionFromWire(candidate, typ, query)
			if typ == 5 {
				_, err = standardengine.ResolvedDNSSECAliasQuestionFromWire(candidate, query)
			}
			if err == nil {
				name, kind = candidate, typ
				break
			}
		}
		if name != "" {
			break
		}
	}
	if name == "" || (mode != "dnssec-cname" && mode != "dnssec-dname") || ip.To4() == nil {
		return nil, false, false, errors.New("alias fixture refused foreign name/type")
	}
	answer := make([]byte, 12)
	copy(answer[:2], query[:2])
	answer[2], answer[3], answer[5] = 0x81, 0xa0, 1
	answer = append(answer, bootHostnameAliasName(name)...)
	answer = append(answer, byte(kind>>8), byte(kind), 0, 1)
	record := func(owner string, typ uint16, data []byte) {
		answer[7]++
		answer = append(answer, bootHostnameAliasName(owner)...)
		answer = append(answer, byte(typ>>8), byte(typ), 0, 1, 0, 0, 0, 30, byte(len(data)>>8), byte(len(data)))
		answer = append(answer, data...)
	}
	if name == bootHostnameFixtureName {
		if mode == "dnssec-dname" {
			record("transport-bootstrap.invalid", 39, bootHostnameAliasName("alias-bootstrap.invalid"))
		}
		record(name, 5, bootHostnameAliasName(bootHostnameAliasTarget))
	} else if kind == 1 {
		record(name, 1, ip.To4())
	}
	return answer, name == bootHostnameAliasTarget, kind == 5, nil
}

func TestLinuxStandardServiceBootHostnameAliasFixtureWire(t *testing.T) {
	for _, mode := range []string{"dnssec-cname", "dnssec-dname"} {
		t.Run(mode, func(t *testing.T) {
			for _, six := range []bool{false, true} {
				original, err := dnsmeasure.TransportBootstrapQuery(bootHostnameFixtureName, six)
				if err != nil {
					t.Fatal(err)
				}
				for _, proof := range []bool{false, true} {
					query := original
					if proof {
						query, err = systembootstrap.ResolvedAliasQuery(original, bootHostnameFixtureName, 5)
						if err != nil {
							t.Fatal(err)
						}
					}
					response, target, typed, err := bootHostnameAliasDNSReply(query, mode, net.ParseIP("192.0.2.44"))
					if err != nil || target || typed != proof || response[3]&0x20 == 0 {
						t.Fatal("alias fixture lost deliberately untrusted AD or exact question", err)
					}
					step, err := systembootstrap.ResolvedAliasStep(query, response)
					if err != nil || step == nil || step.Target != bootHostnameAliasTarget || step.DNAME != (mode == "dnssec-dname") {
						t.Fatal("alias fixture wire changed substitution", step, err)
					}
				}
				kind := uint16(1)
				if six {
					kind = 28
				}
				query, err := systembootstrap.ResolvedAliasQuery(original, bootHostnameAliasTarget, kind)
				if err != nil {
					t.Fatal(err)
				}
				response, target, typed, err := bootHostnameAliasDNSReply(query, mode, net.ParseIP("192.0.2.44"))
				if err != nil || !target || typed || !six && (binary.BigEndian.Uint16(response[6:8]) != 1 || !bytes.Equal(response[len(response)-4:], []byte{192, 0, 2, 44})) || six && binary.BigEndian.Uint16(response[6:8]) != 0 {
					t.Fatal("target did not retain original Node address", err)
				}
				query, err = systembootstrap.ResolvedAliasQuery(original, "foreign.alias-bootstrap.invalid", 1)
				if err != nil {
					t.Fatal(err)
				}
				if _, _, _, err = bootHostnameAliasDNSReply(query, mode, net.ParseIP("192.0.2.44")); err == nil {
					t.Fatal("foreign alias target answered")
				}
			}
		})
	}
}
