//go:build linux && routervpn_linux_guardian

package mobiletor

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const desktopLinuxDormantDeniedPayload = "routervpn-dormant-owner-must-not-send"

func init() {
	if len(os.Args) == 2 && os.Args[1] == "routervpn-linux-flags-peer" {
		if err := desktopLinuxFlagsPeer(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(86)
		}
		os.Exit(0)
	}
}

func desktopLinuxFlagsPeer() error {
	if os.Getenv("ROUTERVPN_LINUX_GUARDIAN_TEST_NS") != "1" {
		return errors.New("Linux flag peer requires its isolated namespace")
	}
	peer, err := net.ListenPacket("udp4", "198.18.0.2:0")
	if err != nil {
		return err
	}
	defer peer.Close()
	if _, err = fmt.Fprintln(os.Stdout, peer.LocalAddr()); err != nil {
		return err
	}
	var denied atomic.Uint64
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		buffer := make([]byte, 256)
		for {
			n, address, err := peer.ReadFrom(buffer)
			if err != nil {
				return
			}
			if string(buffer[:n]) == desktopLinuxDormantDeniedPayload {
				denied.Add(1)
			}
			_ = peer.SetWriteDeadline(time.Now().Add(time.Second))
			if _, err = peer.WriteTo(buffer[:n], address); err != nil {
				return
			}
		}
	}()
	defer func() { _ = peer.Close(); <-joined }()
	reader := bufio.NewReaderSize(os.Stdin, 32)
	for {
		line, err := reader.ReadString('\n')
		if errors.Is(err, io.EOF) && line == "" {
			return nil
		}
		if err != nil || line != "count\n" {
			return errors.New("Linux flag peer lost its exact captured observation command")
		}
		if _, err = fmt.Fprintln(os.Stdout, denied.Load()); err != nil {
			return err
		}
	}
}

func desktopLinuxKernelFlagPeer(t *testing.T) (netip.AddrPort, func() uint64) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	command := exec.CommandContext(ctx, "ip", "netns", "exec", "rvpn-peer", executable, "routervpn-linux-flags-peer")
	command.Stderr = os.Stderr
	input, err := command.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
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
		_ = input.Close()
		if err := command.Wait(); err != nil {
			t.Error("actual independent flag peer did not join", err)
		}
		cancel()
	})
	reader := bufio.NewReader(output)
	line, err := reader.ReadString('\n')
	remote, parseErr := netip.ParseAddrPort(strings.TrimSpace(line))
	if err != nil || parseErr != nil || remote.Addr() != netip.MustParseAddr("198.18.0.2") || remote.Port() == 0 {
		t.Fatal("actual flag peer did not return its bounded endpoint", err, parseErr)
	}
	return remote, func() uint64 {
		if _, err := io.WriteString(input, "count\n"); err != nil {
			t.Fatal(err)
		}
		line, err := reader.ReadString('\n')
		count, parseErr := strconv.ParseUint(strings.TrimSpace(line), 10, 64)
		if err != nil || parseErr != nil {
			t.Fatal("actual flag peer lost its independent observation", err, parseErr)
		}
		return count
	}
}

// This fixture uses an independent native rendering for the dormant bit.
// nftables 1.0.9 can render JSON flags using unrelated inventory strings;
// production must reject those unknown values, never interpret them as active.
func desktopLinuxDormantFlagReadback(ctx context.Context) (string, error) {
	raw, err := desktopLinuxNFTCommand(ctx, []string{"-n", "list", "table", "inet", desktopLinuxNFTTable}, "")
	if err != nil || !strings.HasPrefix(string(raw), "table inet "+desktopLinuxNFTTable+" {\n") {
		return "", errors.Join(err, errors.New("dormant fixture lost its exact native table listing"))
	}
	var flags string
	for _, line := range strings.Split(string(raw), "\n") {
		if value := strings.TrimSpace(line); strings.HasPrefix(value, "flags ") {
			if flags != "" || value != "flags dormant" && value != "flags dormant;" {
				return "", errors.New("dormant fixture received ambiguous native table flags")
			}
			flags = value
		}
	}
	if flags == "" {
		return "", errors.New("dormant fixture did not read the actual disabled table flag")
	}
	return flags, nil
}

func TestDesktopLinuxGuardianKernelRejectsDormantTable(t *testing.T) {
	t.Run("running-owner-heartbeat", func(t *testing.T) {
		remote, receivedDenied := desktopLinuxKernelFlagPeer(t)
		p := desktopLinuxKernelPolicy(t, []DesktopLinuxSocketDestination{{Network: "udp", Address: remote}})
		broker := desktopLinuxKernelBroker(t, p)
		connection, err := broker.DialContext(context.Background(), "udp4", remote.String())
		if err != nil {
			t.Fatal(err)
		}
		positive := []byte("actual guarded owner before table dormancy")
		connection.SetDeadline(time.Now().Add(time.Second))
		if _, err = connection.Write(positive); err != nil {
			t.Fatal(err)
		}
		var answer [128]byte
		if count, err := connection.Read(answer[:]); err != nil || !bytes.Equal(answer[:count], positive) || receivedDenied() != 0 {
			t.Fatal("actual peer baseline was not a positive owned transfer", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		// Serialize with the real request stream so a concurrent monitor cannot
		// hide whether this exact native heartbeat accepted the disabled table.
		p.mu.Lock()
		observed := p.observed.Load()
		_, changeErr := desktopLinuxNFTCommand(ctx, []string{"-f", "-"}, "add table inet router_vpn_killswitch { flags dormant; }\n")
		dormantRows, flagsErr := desktopLinuxNFTRead(ctx)
		var capturedFlags any
		capturedTable := false
		for _, row := range dormantRows {
			if table, ok := row["table"].(map[string]any); ok && table["family"] == "inet" && table["name"] == desktopLinuxNFTTable && desktopLinuxNumber(table["handle"]) == p.nft.TableHandle {
				capturedFlags, capturedTable = table["flags"]
			}
		}
		capturedNativeFlags, nativeFlagsErr := desktopLinuxDormantFlagReadback(ctx)
		_, file, heartbeatErr := p.callLocked(ctx, desktopLinuxRequest{Operation: "probe", Capture: p.capture}, nil, true)
		current, refreshed := p.current.Load(), p.observed.Load() != observed
		p.mu.Unlock()
		if file != nil {
			_ = file.Close()
		}
		if changeErr != nil || flagsErr != nil || nativeFlagsErr != nil || !capturedTable || heartbeatErr == nil || file != nil || current || refreshed || p.Current(p.capture, p.owner) {
			t.Fatal("actual heartbeat accepted the dormant native baseline", changeErr, flagsErr, nativeFlagsErr, heartbeatErr, current, refreshed)
		}
		if count, err := connection.Write([]byte(desktopLinuxDormantDeniedPayload)); count != 0 || err == nil {
			t.Fatal("dormant native source acknowledged unguarded bytes", count, err)
		}
		// Prove that the independent peer is still reachable while the table is
		// dormant; failure of that peer cannot masquerade as source rejection.
		plain, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(remote))
		if err != nil {
			t.Fatal(err)
		}
		defer plain.Close()
		plain.SetDeadline(time.Now().Add(time.Second))
		if _, err = plain.Write(positive); err != nil {
			t.Fatal(err)
		}
		if count, err := plain.Read(answer[:]); err != nil || !bytes.Equal(answer[:count], positive) || receivedDenied() != 0 {
			t.Fatal("dormant source rejection had no independent live-peer witness", err)
		}
		if err = connection.Close(); err != nil {
			t.Fatal(err)
		}
		if err = broker.Close(ctx); err != nil {
			t.Fatal("inactive baseline prevented exact native permit retirement", err)
		}
		if err = p.nft.allAbsent(ctx); err != nil || receivedDenied() != 0 {
			t.Fatal("dormant native owner retained permits or leaked its rejected marker", err)
		}
		rows, err := desktopLinuxNFTRead(ctx)
		keptTable := false
		var tableHandle uint64
		var tableFlags any
		for _, row := range rows {
			if table, ok := row["table"].(map[string]any); ok && table["family"] == "inet" && table["name"] == desktopLinuxNFTTable {
				tableHandle, tableFlags = desktopLinuxNumber(table["handle"]), table["flags"]
				keptTable = tableHandle == p.nft.TableHandle && !desktopLinuxNFTTableActive(table)
			}
		}
		baseline := &desktopLinuxNFT{Baseline: make(map[uint64]any)}
		baselineErr := baseline.captureBaseline(rows, p.options)
		sameBaseline := reflect.DeepEqual(baseline.Baseline, p.nft.Baseline)
		nativeFlags, nativeFlagsErr := desktopLinuxDormantFlagReadback(ctx)
		if err != nil || !keptTable || baselineErr != nil || !sameBaseline || nativeFlagsErr != nil || nativeFlags != capturedNativeFlags {
			t.Fatal("exact cleanup changed or adopted the disabled baseline", err, "table handles", tableHandle, p.nft.TableHandle, "JSON flags", tableFlags, capturedFlags, "native flags", nativeFlags, capturedNativeFlags, nativeFlagsErr, "baseline", baselineErr, sameBaseline)
		}
	})

	t.Run("preparation-before-account-creation", func(t *testing.T) {
		p := desktopLinuxKernelPolicy(t, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := p.Close(ctx); err != nil {
			t.Fatal(err)
		}
		desktopLinuxProtectionNativeCommand(t, "add table inet router_vpn_killswitch { flags dormant; }\n")
		before, err := os.ReadDir(desktopLinuxIdentities)
		if err != nil {
			t.Fatal(err)
		}
		failed, prepareErr := NewDesktopLinuxSocketPolicy(ctx, p.capture, p.options)
		if failed != nil {
			if err := failed.Close(ctx); err != nil {
				t.Fatal("disabled-table partial preparation did not join", err)
			}
		}
		after, err := os.ReadDir(desktopLinuxIdentities)
		beforeNames, afterNames := make([]string, 0, len(before)), make([]string, 0, len(after))
		for _, entry := range before {
			beforeNames = append(beforeNames, entry.Name())
		}
		for _, entry := range after {
			afterNames = append(afterNames, entry.Name())
		}
		if prepareErr == nil || err != nil || !reflect.DeepEqual(beforeNames, afterNames) {
			t.Fatal("disabled baseline created an isolated account before native refusal", prepareErr, err)
		}
	})
}
