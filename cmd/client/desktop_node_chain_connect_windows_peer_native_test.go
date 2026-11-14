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
	"strings"
	"testing"
	"time"
)

type windowsCONNECTPeerReply struct {
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
	Protocol        string `json:"connect_protocol"`
	ConnectCA       string `json:"connect_ca"`
	ServerName      string `json:"connect_server_name"`
	AuthRefusals    int64  `json:"connect_auth_refusals"`
	TargetRefusals  int64  `json:"connect_target_refusals"`
	TLSRefusals     int64  `json:"connect_tls_refusals"`
	OpenStreams     *int   `json:"open_connect_streams"`
	FinalUOTVersion int    `json:"final_uot_version"`
}

func windowsCONNECTPeerStart(t *testing.T, mode, protocol string) (*windowsPrefixPeer, string, string, string, func(string) windowsCONNECTPeerReply) {
	t.Helper()
	if protocol != "http-connect" && protocol != "https-connect" {
		t.Fatal("original CONNECT protocol required")
	}
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
	command := exec.Command(imageCapture.Path(), "-test.run=^TestRouterVPNDesktopWindowsCONNECTReferenceProcess$", "-test.count=1", "-test.timeout=240s")
	command.Env = append(os.Environ(), "ROUTERVPN_WINDOWS_PREFIX_REFERENCE=1", "ROUTERVPN_CONNECT_INSTALLED_REFERENCE=1")
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, peerOutput, err := os.Pipe()
	if err != nil {
		input.Close()
		t.Fatal(err)
	}
	command.Stdout = peerOutput
	diagnostic := new(windowsPrefixOutput)
	command.Stderr = diagnostic
	if err := command.Start(); err != nil {
		input.Close()
		peerOutput.Close()
		output.Close()
		t.Fatal(err)
	}
	if err := peerOutput.Close(); err != nil {
		command.Process.Kill()
		command.Wait()
		input.Close()
		output.Close()
		t.Fatal(err)
	}
	process, err := windowscontroller.OpenProcess(uint32(command.Process.Pid))
	if err != nil {
		command.Process.Kill()
		command.Wait()
		input.Close()
		output.Close()
		t.Fatal(err)
	}
	if err := process.VerifyImage(imageCapture); err != nil {
		command.Process.Kill()
		command.Wait()
		input.Close()
		output.Close()
		process.Close()
		t.Fatal(err)
	}
	reader := bufio.NewReaderSize(output, 32769)
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	t.Cleanup(func() {
		input.Close()
		type remainder struct {
			raw []byte
			err error
		}
		tail := make(chan remainder, 1)
		go func() { raw, err := io.ReadAll(io.LimitReader(reader, 65537)); tail <- remainder{raw, err} }()
		select {
		case err := <-done:
			if err != nil {
				t.Error("encrypted CONNECT peer did not join", err, diagnostic.String())
			}
		case <-time.After(5 * time.Second):
			command.Process.Kill()
			<-done
			t.Error("encrypted CONNECT peer forced termination", diagnostic.String())
		}
		trailer := <-tail
		output.Close()
		if trailer.err != nil || len(trailer.raw) > 65536 || strings.Count(string(trailer.raw), "CONNECT_INSTALLED_PEER_JOINED\n") != 1 || strings.Contains(string(trailer.raw), "FAIL") || strings.Contains(string(trailer.raw), "SKIP") {
			t.Error("original CONNECT peer omitted its joined encrypted-provider receipt", trailer.err, string(trailer.raw))
		}
		if err := process.Close(); err != nil {
			t.Error(err)
		}
	})
	var physical struct {
		Schema  int    `json:"schema"`
		Address string `json:"physical_address"`
	}
	windowsPrefixRead(t, reader, &physical)
	if physical.Schema != 1 || physical.Address == "" {
		t.Fatal("prefix peer omitted actual current physical interface")
	}
	request := map[string]any{"schema": 1, "address": physical.Address, "client_address": physical.Address, "prefixes": peer.requests, "final_password": peer.password, "final_node_proof_id": windowsPrefixProofID(peer.finalServer), "final_api_token": "installed-ordered-final-token", "benchmark_port": 45998}
	if err := json.NewEncoder(input).Encode(map[string]any{"schema": 1, "paired": request, "middle_method": mobilemultihop.NativeStartLayerMethod, "middle_password": middlePassword, "protocol": protocol}); err != nil {
		t.Fatal(err)
	}
	var first windowsCONNECTPeerReply
	windowsPrefixRead(t, reader, &first)
	peer.reply = first.windowsPrefixPeerReply
	if peer.reply.Schema != 1 || peer.reply.Address != net.JoinHostPort(physical.Address, "51820") || len(peer.reply.Prefixes) != 1 || first.Middle.Method != protocol || first.Protocol != protocol || first.OpenStreams == nil || first.FinalUOTVersion != 2 || peer.reply.PublicCA == "" {
		t.Fatal("prefix peer changed original physical/key inventory")
	}
	if protocol == "https-connect" && (first.ConnectCA == "" || first.ConnectCA == first.PublicCA || first.ServerName != "speed.cloudflare.com") || protocol == "http-connect" && (first.ConnectCA != "" || first.ServerName != "") {
		t.Fatal("CONNECT peer changed exact protocol or independent TLS authority")
	}
	return peer, middlePassword, first.ConnectCA, first.ServerName, func(action string) windowsCONNECTPeerReply {
		if _, err := io.WriteString(input, action+"\n"); err != nil {
			t.Fatal(err)
		}
		var value windowsCONNECTPeerReply
		windowsPrefixRead(t, reader, &value)
		if value.Address != peer.reply.Address || value.PublicCA != peer.reply.PublicCA || value.Protocol != first.Protocol || value.ConnectCA != first.ConnectCA || value.ServerName != first.ServerName || value.FinalUOTVersion != 2 || value.OpenStreams == nil {
			t.Fatal("prefix peer replaced original identity")
		}
		return value
	}
}
