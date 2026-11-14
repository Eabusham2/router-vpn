//go:build windows && routervpn_windows_candidate_prefix_native && go1.25

package main

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/windowscontroller"
	"testing"
	"time"
)

type windowsSOCKSPeerReply struct {
	windowsPrefixPeerReply
	Middle struct {
		Method        string `json:"method"`
		RawTCP        int64  `json:"raw_tcp"`
		RawUDP        int64  `json:"raw_udp"`
		TCP           int64  `json:"tcp"`
		UDP           int64  `json:"udp"`
		PublicQueries uint64 `json:"public_queries"`
		DownloadBytes uint64 `json:"download_bytes"`
		UploadBytes   uint64 `json:"upload_bytes"`
	} `json:"middle"`
	Associations *int `json:"associations"`
}

func windowsSOCKSPeerStart(t *testing.T, mode string) (*windowsPrefixPeer, string, func(string) windowsSOCKSPeerReply) {
	t.Helper()
	peer := windowsPrefixPeerKeys(t, 3)
	middlePassword := peer.requests[1].PreSharedKey
	peer.requests, peer.clients = peer.requests[:1], peer.clients[:1]
	windowsPrefixSetModes(t, peer, []string{mode})
	image := os.Getenv("ROUTERVPN_WINDOWS_PREFIX_PEER")
	if !filepath.IsAbs(image) {
		t.Fatal("prefix peer requires original compiled image")
	}
	imageCapture, err := windowscontroller.PinImage(image)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := imageCapture.Close(); err != nil {
			t.Error(err)
		}
	})
	command := exec.Command(imageCapture.Path(), "-test.run=^TestRouterVPNDesktopWindowsSOCKSReferenceProcess$", "-test.count=1", "-test.timeout=100s")
	command.Env = append(os.Environ(), "ROUTERVPN_WINDOWS_PREFIX_REFERENCE=1", "ROUTERVPN_SOCKS_INSTALLED_REFERENCE=1")
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	diagnostic := new(windowsPrefixOutput)
	command.Stderr = diagnostic
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	process, err := windowscontroller.OpenProcess(uint32(command.Process.Pid))
	if err != nil {
		command.Process.Kill()
		command.Wait()
		t.Fatal(err)
	}
	if err := process.VerifyImage(imageCapture); err != nil {
		command.Process.Kill()
		command.Wait()
		process.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	t.Cleanup(func() {
		input.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error("encrypted prefix peer did not join", err, diagnostic.String())
			}
		case <-time.After(5 * time.Second):
			command.Process.Kill()
			<-done
			t.Error("encrypted prefix peer forced termination", diagnostic.String())
		}
		output.Close()
		if err := process.Close(); err != nil {
			t.Error(err)
		}
	})
	reader := bufio.NewReaderSize(output, 32769)
	var physical struct {
		Schema  int    `json:"schema"`
		Address string `json:"physical_address"`
	}
	windowsPrefixRead(t, reader, &physical)
	if physical.Schema != 1 || physical.Address == "" {
		t.Fatal("prefix peer omitted actual current physical interface")
	}
	request := map[string]any{"schema": 1, "address": physical.Address, "client_address": physical.Address, "prefixes": peer.requests, "final_password": peer.password, "final_node_proof_id": windowsPrefixProofID(peer.finalServer), "final_api_token": "installed-ordered-final-token"}
	if err := json.NewEncoder(input).Encode(map[string]any{"schema": 1, "paired": request, "middle_method": mobilemultihop.NativeStartLayerMethod, "middle_password": middlePassword}); err != nil {
		t.Fatal(err)
	}
	var first windowsSOCKSPeerReply
	windowsPrefixRead(t, reader, &first)
	peer.reply = first.windowsPrefixPeerReply
	if peer.reply.Schema != 1 || peer.reply.Address != net.JoinHostPort(physical.Address, "51820") || len(peer.reply.Prefixes) != 1 || first.Middle.Method != "socks5" || first.Associations == nil || peer.reply.PublicCA == "" {
		t.Fatal("prefix peer changed original physical/key inventory")
	}
	return peer, middlePassword, func(action string) windowsSOCKSPeerReply {
		if _, err := io.WriteString(input, action+"\n"); err != nil {
			t.Fatal(err)
		}
		var value windowsSOCKSPeerReply
		windowsPrefixRead(t, reader, &value)
		if value.Address != peer.reply.Address || value.PublicCA != peer.reply.PublicCA {
			t.Fatal("prefix peer replaced original identity")
		}
		return value
	}
}
