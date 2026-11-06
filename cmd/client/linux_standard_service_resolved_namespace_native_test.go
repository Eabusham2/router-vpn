//go:build linux && routervpn_controller_privileged

package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

var linuxHostTUNResolvedCases = []string{"service-boot-resolved-udp", "service-boot-resolved-tcp", "service-boot-resolved-local", "service-boot-resolved-parallel", "service-boot-resolved-opportunistic-tls", "service-boot-resolved-opportunistic-fallback", "service-boot-resolved-dnssec-nta", "service-boot-resolved-dnssec-cname", "service-boot-resolved-dnssec-dname", "service-boot-resolved-dnssec-private-tld", "service-boot-resolved-dnssec-private-tld-unrelated-nta"}

func init() { linuxHostTUNCases = append(linuxHostTUNCases, linuxHostTUNResolvedCases...) }
func linuxHostTUNResolvedCase(scenario string) bool {
	for _, name := range linuxHostTUNResolvedCases {
		if scenario == name {
			return true
		}
	}
	return false
}

func linuxHostTUNResolvedBroker(t *testing.T, peer *linuxHostTUNPeer, scenario string, rootDS []byte) {
	privateTLD := strings.HasPrefix(scenario, "service-boot-resolved-dnssec-private-tld")
	t.Helper()
	// The host runner has already proved private original mount/net namespaces.
	// Hide the outer bus using a bind mount; never rename or modify its socket.
	linuxHostTUNNamespaceIdentity(t)
	target := "/run/dbus"
	var filesystem syscall.Statfs_t
	if syscall.Statfs("/run", &filesystem) != nil || filesystem.Type != 0x01021994 {
		t.Fatal("composition runtime is not the runner's private tmpfs")
	}
	if err := os.Mkdir(target, 0755); err != nil {
		t.Fatal("private bus directory was unexpectedly present", err)
	}
	t.Cleanup(func() {
		if err := os.Remove(target); err != nil {
			t.Error(err)
		}
	})
	before, err := os.Lstat(target)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		t.Fatal("composition gate needs existing native bus directory", err)
	}
	directory, err := os.MkdirTemp("/opt", "resolved-composition-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	bus := filepath.Join(directory, "bus")
	if err = os.Mkdir(bus, 0755); err != nil {
		t.Fatal(err)
	}
	if err = syscall.Mount(bus, target, "", syscall.MS_BIND, ""); err != nil {
		t.Fatal("private original-broker mount", err)
	}
	t.Cleanup(func() {
		if err := syscall.Unmount(target, 0); err != nil {
			t.Error(err)
		}
		after, err := os.Lstat(target)
		if err != nil || !os.SameFile(before, after) {
			t.Error("original outer bus directory changed", err)
		}
	})
	image := filepath.Join(directory, "broker.test")
	linuxHostTUNCopy(t, os.Getenv("ROUTERVPN_NODE_HOST_PEER_BINARY"), image, 512<<20, os.Getenv("ROUTERVPN_NODE_HOST_PEER_SHA256"), 0755)
	countFile := filepath.Join(directory, "local-preflights")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	command := exec.CommandContext(ctx, image, "-test.run=^TestRouterVPNResolvedInstalledBroker$", "-test.timeout=100s")
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "GORACE=atexit_sleep_ms=0", "ROUTERVPN_RESOLVED_COMPOSITION_BROKER=1", "ROUTERVPN_RESOLVED_COMPOSITION_ANSWER=" + peer.address.Addr().String(), "ROUTERVPN_RESOLVED_COMPOSITION_COUNT=" + countFile}
	if scenario == "service-boot-resolved-local" {
		command.Env = append(command.Env, "ROUTERVPN_RESOLVED_COMPOSITION_LOCAL=1")
	}
	if scenario == "service-boot-resolved-parallel" {
		command.Env = append(command.Env, "ROUTERVPN_RESOLVED_COMPOSITION_PARALLEL=1")
	}
	if scenario == "service-boot-resolved-opportunistic-tls" || scenario == "service-boot-resolved-opportunistic-fallback" {
		command.Env = append(command.Env, "ROUTERVPN_RESOLVED_COMPOSITION_OPPORTUNISTIC=1")
	}
	if privateTLD {
		if len(rootDS) == 0 {
			t.Fatal("original broker omitted private root authority")
		}
		command.Env = append(command.Env, "ROUTERVPN_RESOLVED_COMPOSITION_PRIVATE_TLD="+base64.StdEncoding.EncodeToString(rootDS))
		if strings.HasSuffix(scenario, "-unrelated-nta") {
			command.Env = append(command.Env, "ROUTERVPN_RESOLVED_COMPOSITION_UNRELATED_NTA=1")
		}
	} else if strings.HasPrefix(scenario, "service-boot-resolved-dnssec-") {
		command.Env = append(command.Env, "ROUTERVPN_RESOLVED_COMPOSITION_DNSSEC_NTA=1")
		if scenario != "service-boot-resolved-dnssec-nta" {
			command.Env = append(command.Env, "ROUTERVPN_RESOLVED_COMPOSITION_ALIAS="+strings.TrimPrefix(scenario, "service-boot-resolved-dnssec-"))
		}
	}
	command.Stderr = os.Stderr
	output, err := command.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err = command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = command.Wait()
		body, err := os.ReadFile(countFile)
		count, parse := strconv.Atoi(string(body))
		minimum := 5
		if scenario == "service-boot-resolved-local" {
			minimum = 1
		}
		if err != nil || parse != nil || count < minimum {
			t.Error("installed shipping helper omitted original local-only preflights", err, parse, count)
		}
		mutations, mutationErr := os.ReadFile(countFile + ".mutations")
		mutationCount, mutationParse := strconv.Atoi(string(mutations))
		if mutationErr != nil || mutationParse != nil || mutationCount < 3 || mutationCount%3 != 0 {
			t.Error("installed TUN omitted original post-helper DNS ownership", mutationErr, mutationParse, mutationCount)
		}
		if privateTLD {
			raw, err := os.ReadFile(countFile + ".anchor-names")
			var names map[string]int
			if err != nil || json.Unmarshal(raw, &names) != nil {
				t.Error("private root plan receipts missing", err)
			}
			total := names["node.private/43"]
			if total < 6 {
				t.Error("private-TLD omitted complete ordinary plus auxiliary plan checkpoints", total)
			}
			for _, name := range []string{"node.private", "private", "."} {
				if names[name+"/43"] != total || names[name+"/48"] != total {
					t.Error("private-TLD dropped original positive/absent observation", name, names)
				}
			}
			monitor, err := os.ReadFile(countFile + ".monitor")
			n, parse := strconv.Atoi(string(monitor))
			if err != nil || parse != nil || n < 1 {
				t.Error("private-TLD omitted same-original monitor refusal", err, parse, n)
			}
			t.Logf("verified installed private-TLD original complete root plan and monitor: %s", scenario)
		}
		if scenario == "service-boot-resolved-dnssec-nta" {
			body, err := os.ReadFile(countFile + ".anchors")
			count, parse := strconv.Atoi(string(body))
			if err != nil || parse != nil || count < 24 || count%24 != 0 {
				t.Error("installed DNSSEC omitted full original absent-anchor capture/recheck", err, parse, count)
			}
			t.Log("verified installed DNSSEC original NTA and absent-anchor recheck")
		}
		if scenario == "service-boot-resolved-dnssec-cname" || scenario == "service-boot-resolved-dnssec-dname" {
			raw, err := os.ReadFile(countFile + ".anchor-names")
			var names map[string]int
			if err != nil || json.Unmarshal(raw, &names) != nil {
				t.Error("alias trust observations missing", err)
			}
			for _, name := range []string{"node.transport-bootstrap.invalid", "transport-bootstrap.invalid", "node.alias-bootstrap.invalid", "alias-bootstrap.invalid"} {
				ds, key := names[name+"/43"], names[name+"/48"]
				if ds < 3 || ds%3 != 0 || ds != key {
					t.Error("alias target omitted original capture/postjoin/adoption", name, ds, key)
				}
			}
			for _, suffix := range []string{"invalid", "."} {
				total := names["node.transport-bootstrap.invalid/43"] + names["node.alias-bootstrap.invalid/43"]
				if names[suffix+"/43"] != total || names[suffix+"/48"] != total {
					t.Error("alias trust cohort omitted a common ancestor", suffix, names)
				}
			}
			if names["target-local"] < 3 || names["node.transport-bootstrap.invalid/43"] < names["node.alias-bootstrap.invalid/43"] {
				t.Error("alias reused original name authority", names)
			}
			t.Logf("verified installed DNSSEC alias target independently captured and adopted: %s", scenario)
		}
		t.Logf("verified installed resolved helper original broker and scoped upstream: %s", scenario)
	})
	if line, err := bufio.NewReader(output).ReadString('\n'); err != nil || line != "original resolved composition broker ready\n" {
		t.Fatal("original isolated broker did not become ready", line, err)
	}
}

func linuxHostTUNNamespaceIdentity(t *testing.T) {
	t.Helper()
	// The mandatory runner captures the outer mount identity before entering
	// its private mount namespace; a private-net marker alone is insufficient.
	if os.Getenv("ROUTERVPN_LINUX_GUARDIAN_TEST_NS") != "1" || os.Geteuid() != 0 {
		t.Fatal("resolved composition escaped original isolated root")
	}
	// Verify mount propagation is private: the existing native host driver
	// creates its mount namespace before any installed fixture is dispatched.
	// The outer identity is supplied below by the mandatory runner inventory.
	outer := os.Getenv("ROUTERVPN_RESOLVED_OUTER_MNTNS_ID")
	var stat syscall.Stat_t
	if syscall.Stat("/proc/self/ns/mnt", &stat) != nil || outer == "" || outer == strconv.FormatUint(uint64(stat.Dev), 10)+":"+strconv.FormatUint(stat.Ino, 10) {
		t.Fatal("resolved composition lacks distinct original mount namespace")
	}
}
