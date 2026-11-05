//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func standardGenerationTestRoot(t *testing.T) string {
	t.Helper()
	root, err := os.MkdirTemp("/run", "rvg-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	return root
}
func standardGenerationTestFiles(t *testing.T, root string, image []byte, version string) string {
	t.Helper()
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	digest := func(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
	manifest := linuxStandardGenerationManifestData{Schema: 1, Files: []linuxStandardGenerationEntry{{Path: "README", Mode: 0644, SHA256: digest([]byte(version))}, {Path: "router-vpn-client", Mode: 0755, SHA256: digest(image)}}}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	id := digest(raw)
	store := root + ".service-generations"
	directory := filepath.Join(store, id)
	if err = os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{"README": []byte(version), "router-vpn-client": image, linuxStandardGenerationManifest: raw} {
		mode := os.FileMode(0644)
		if name == "router-vpn-client" {
			mode = 0755
		}
		if name == linuxStandardGenerationManifest {
			mode = 0600
		}
		if err = os.WriteFile(filepath.Join(directory, name), body, mode); err != nil {
			t.Fatal(err)
		}
	}
	if err = os.WriteFile(directory+".lock", nil, 0600); err != nil {
		t.Fatal(err)
	}
	activation, err := json.Marshal(linuxStandardGenerationSelection{Schema: 1, Generation: id, ImageSHA256: digest(image)})
	if err != nil {
		t.Fatal(err)
	}
	temporary := filepath.Join(root, "next-activation")
	if err = os.WriteFile(temporary, activation, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(temporary, filepath.Join(root, linuxStandardGenerationActivation)); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestLinuxStandardServiceGenerationRejectsChangedSource(t *testing.T) {
	for _, kind := range []string{"current", "legacy", "bad-code", "undeclared", "linked-image", "unsafe-mode", "changed-manifest", "foreign-lock", "bad-activation", "activation-link", "activation-trailing", "expired"} {
		t.Run(kind, func(t *testing.T) {
			root := filepath.Join(standardGenerationTestRoot(t), "root")
			directory := standardGenerationTestFiles(t, root, []byte("exact executable"), "one")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			switch kind {
			case "legacy":
				os.Remove(filepath.Join(root, linuxStandardGenerationActivation))
			case "bad-code":
				os.WriteFile(filepath.Join(directory, "router-vpn-client"), []byte("foreign executable"), 0755)
			case "undeclared":
				os.WriteFile(filepath.Join(directory, "foreign"), []byte("not declared"), 0600)
			case "linked-image":
				original := filepath.Join(directory, "router-vpn-client")
				os.Rename(original, original+".old")
				os.Symlink(original+".old", original)
			case "unsafe-mode":
				os.Chmod(filepath.Join(directory, "router-vpn-client"), 0777)
			case "changed-manifest":
				os.WriteFile(filepath.Join(directory, linuxStandardGenerationManifest), []byte(`{"schema":1,"files":[]}`), 0600)
			case "foreign-lock":
				os.Remove(directory + ".lock")
				os.Symlink(filepath.Join(directory, "README"), directory+".lock")
			case "bad-activation":
				os.WriteFile(filepath.Join(root, linuxStandardGenerationActivation), []byte(`{"schema":1,"generation":"../other"}`), 0600)
			case "activation-link":
				path := filepath.Join(root, linuxStandardGenerationActivation)
				os.Rename(path, path+".old")
				os.Symlink(path+".old", path)
			case "activation-trailing":
				path := filepath.Join(root, linuxStandardGenerationActivation)
				raw, _ := os.ReadFile(path)
				os.WriteFile(path, append(raw, []byte("{}")...), 0600)
			case "expired":
				cancel()
			}
			generation, err := captureLinuxStandardServiceGeneration(ctx, root)
			if kind == "current" {
				if err != nil || generation == nil {
					t.Fatal(err)
				}
				defer generation.Close()
				if err = generation.Current(ctx); err != nil {
					t.Fatal(err)
				}
				return
			}
			if kind == "legacy" {
				if err != nil || generation != nil {
					t.Fatal("legacy install did not retain exact canonical image path", err)
				}
				return
			}
			if err == nil {
				if generation != nil {
					generation.Close()
				}
				t.Fatal("changed source became a service generation")
			}
			if kind == "expired" && !errors.Is(err, context.Canceled) {
				t.Fatal("original cancellation cause lost", err)
			}
		})
	}
}

func TestLinuxStandardServiceGenerationExpiryKeepsOriginalLease(t *testing.T) {
	root := filepath.Join(standardGenerationTestRoot(t), "root")
	directory := standardGenerationTestFiles(t, root, []byte("exact executable"), "one")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	generation, err := captureLinuxStandardServiceGeneration(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	defer generation.Close()
	expired, stop := context.WithCancel(ctx)
	stop()
	if err = generation.Current(expired); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err = generation.Current(ctx); err != nil {
		t.Fatal("pure observation expiry poisoned original generation", err)
	}
	other, err := os.OpenFile(directory+".lock", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err = syscall.Flock(int(other.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); !errors.Is(err, syscall.EWOULDBLOCK) {
		t.Fatal("retained generation no longer excluded source mutation", err)
	}
	if err = os.WriteFile(filepath.Join(directory, "README"), []byte("changed actual source"), 0644); err != nil {
		t.Fatal(err)
	}
	if err = generation.Current(ctx); err == nil || errors.Is(err, context.Canceled) {
		t.Fatal("real source loss was confused with caller expiry", err)
	}
}

func TestLinuxStandardServiceGenerationPeerFixture(t *testing.T) {
	if os.Getenv("ROUTERVPN_GENERATION_TEST_PAIR") == "1" {
		transport := standardServiceTestConnection(t, os.NewFile(3, "generation-original-transport"))
		defer transport.Close()
		for {
			pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			channel := standardServiceTestConnection(t, os.NewFile(uintptr(pair[0]), "generation-original-peer"))
			transfer := os.NewFile(uintptr(pair[1]), "generation-peer-transfer")
			_, _, err = transport.WriteMsgUnix([]byte("R"), syscall.UnixRights(int(transfer.Fd())), nil)
			transfer.Close()
			if err != nil {
				channel.Close()
				return
			}
			generationFixtureReply(channel)
			channel.Close()
		}
	}
	socket := os.Getenv("ROUTERVPN_GENERATION_TEST_SOCKET")
	if socket == "" {
		return
	}
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: socket, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ready := os.NewFile(3, "generation-fixture-ready")
	if _, err = ready.Write([]byte("R")); err != nil {
		t.Fatal(err)
	}
	ready.Close()
	for {
		channel, err := listener.AcceptUnix()
		if err != nil {
			return
		}
		generationFixtureReply(channel)
		channel.Close()
	}
}

func generationFixtureReply(channel *net.UnixConn) {
	body, files, err := linuxStandardServiceRead(channel)
	for _, file := range files {
		file.Close()
	}
	var request linuxStandardServiceRequest
	if err != nil || len(files) != 0 || linuxStandardServiceDecode(body, &request) != nil {
		return
	}
	_ = linuxStandardServiceWrite(channel, linuxStandardServiceResponse{Schema: 1, Action: request.Action, Session: request.Session, Complete: true}, nil)
}

func standardGenerationTestPair(t *testing.T, generation *linuxStandardServiceGeneration) ([]string, func(context.Context) (net.Conn, error)) {
	t.Helper()
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	transport := standardServiceTestConnection(t, os.NewFile(uintptr(pair[0]), "generation-parent-transport"))
	inherited := os.NewFile(uintptr(pair[1]), "generation-child-transport")
	arguments := []string{generation.imagePath, "-test.run=^TestLinuxStandardServiceGenerationPeerFixture$"}
	command := exec.Command(arguments[0], arguments[1:]...)
	command.ExtraFiles = []*os.File{inherited}
	command.Env = append(os.Environ(), "ROUTERVPN_GENERATION_TEST_PAIR=1", "GORACE=atexit_sleep_ms=0")
	if err = command.Start(); err != nil {
		inherited.Close()
		transport.Close()
		t.Fatal(err)
	}
	inherited.Close()
	joined := make(chan error, 1)
	go func() { joined <- command.Wait() }()
	t.Cleanup(func() {
		transport.Close()
		select {
		case <-joined:
		case <-time.After(5 * time.Second):
			command.Process.Kill()
			<-joined
			t.Error("original generation transport did not join child")
		}
	})
	return arguments, func(ctx context.Context) (net.Conn, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			return nil, errors.New("fixture lost original deadline")
		}
		if err := transport.SetReadDeadline(deadline); err != nil {
			return nil, err
		}
		body, files, err := linuxStandardServiceRead(transport)
		if err != nil || string(body) != "R" || len(files) != 1 {
			for _, f := range files {
				f.Close()
			}
			return nil, errors.Join(err, errors.New("original generation peer transfer failed"))
		}
		return standardServiceTestConnection(t, files[0]), nil
	}
}

func standardGenerationTestPeer(t *testing.T, generation *linuxStandardServiceGeneration, directory string) []string {
	t.Helper()
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	arguments := []string{generation.imagePath, "-test.run=^TestLinuxStandardServiceGenerationPeerFixture$"}
	command := exec.Command(arguments[0], arguments[1:]...)
	diagnostic, err := os.CreateTemp(directory, "peer-output-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { diagnostic.Close() })
	command.Stdout, command.Stderr = diagnostic, diagnostic
	command.ExtraFiles = []*os.File{write}
	command.Env = append(os.Environ(), "ROUTERVPN_GENERATION_TEST_SOCKET="+generation.socket(directory), "GORACE=atexit_sleep_ms=0")
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	write.Close()
	joined := make(chan error, 1)
	go func() { joined <- command.Wait() }()
	t.Cleanup(func() {
		command.Process.Kill()
		select {
		case <-joined:
		case <-time.After(5 * time.Second):
			t.Error("generation fixture child failed to join")
		}
	})
	if err = read.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var ready [1]byte
	if _, err = io.ReadFull(read, ready[:]); err != nil || ready[0] != 'R' {
		body, _ := os.ReadFile(diagnostic.Name())
		t.Fatal("actual generation peer did not bind", err, string(body))
	}
	return arguments
}

func TestLinuxStandardServiceGenerationRetainedPeerSurvivesActivation(t *testing.T) {
	standardGenerationRetainedPeer(t, true)
}
func TestLinuxStandardServiceGenerationRetainedPeerSocketPair(t *testing.T) {
	standardGenerationRetainedPeer(t, false)
}
func standardGenerationRetainedPeer(t *testing.T, named bool) {
	directory := standardGenerationTestRoot(t)
	root := filepath.Join(directory, "root")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	image, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	oldPath := standardGenerationTestFiles(t, root, image, "old")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	generation, err := captureLinuxStandardServiceGeneration(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	defer generation.Close()
	var arguments []string
	channels := map[string]func(context.Context) (net.Conn, error){}
	if named {
		arguments = standardGenerationTestPeer(t, generation, directory)
	} else {
		arguments, channels[generation.socket(directory)] = standardGenerationTestPair(t, generation)
	}
	namespace, err := os.Stat("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	var peer *linuxStandardServicePeer
	defer func() {
		if peer != nil {
			peer.Close()
		}
	}()
	call := func(image os.FileInfo, args []string, socket string, g *linuxStandardServiceGeneration) error {
		d := net.Dialer{}
		var connection net.Conn
		var err error
		if named {
			connection, err = d.DialContext(ctx, "unixpacket", socket)
		} else {
			dial := channels[socket]
			if dial == nil {
				return errors.New("cleanup attempted a replacement generation endpoint")
			}
			connection, err = dial(ctx)
		}
		if err != nil {
			return err
		}
		defer connection.Close()
		_, err = linuxStandardServiceExchangeGeneration(ctx, connection.(*net.UnixConn), image, namespace, &peer, linuxStandardServiceRequest{Schema: 1, Session: strings.Repeat("a", 32), Action: "stop"}, nil, args, nil, g)
		return err
	}
	if err = call(generation.imageInfo, arguments, generation.socket(directory), generation); err != nil {
		t.Fatal(err)
	}
	original := peer
	newPath := standardGenerationTestFiles(t, root, image, "new")
	if oldPath == newPath {
		t.Fatal("fixture did not advance generation")
	}
	selectedImage, selectedArgs, socket, newCapability, err := linuxStandardServiceDestination(ctx, root, directory, nil, peer)
	if err != nil || newCapability != nil || socket != generation.socket(directory) || !os.SameFile(selectedImage, generation.imageInfo) {
		if newCapability != nil {
			newCapability.Close()
		}
		t.Fatal("activation redirected retained cleanup", err)
	}
	if err = call(selectedImage, selectedArgs, socket, nil); err != nil || peer != original {
		t.Fatal("original Stop could not reach its retained service", err)
	}
	replacement, err := captureLinuxStandardServiceGeneration(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	var replacementArgs []string
	if named {
		replacementArgs = standardGenerationTestPeer(t, replacement, directory)
	} else {
		replacementArgs, channels[replacement.socket(directory)] = standardGenerationTestPair(t, replacement)
	}
	if err = call(replacement.imageInfo, replacementArgs, replacement.socket(directory), replacement); err == nil || peer != original {
		t.Fatal("new activation adopted a replacement peer", err)
	}
	if err = peer.Current(ctx); err != nil {
		t.Fatal("replacement refusal damaged original cleanup authority", err)
	}
	if err = os.WriteFile(filepath.Join(oldPath, "README"), []byte("changed original code"), 0644); err != nil {
		t.Fatal(err)
	}
	if err = peer.Current(ctx); err == nil {
		t.Fatal("actual source loss remained a current original peer")
	}
}

func TestLinuxStandardServiceGenerationListenerPreventsAbsence(t *testing.T) {
	for _, late := range []bool{false, true} {
		name := "present"
		if late {
			name = "created-during-readback"
		}
		t.Run(name, func(t *testing.T) {
			root := standardGenerationTestRoot(t)
			directory := filepath.Join(root, "svc")
			if err := os.Mkdir(directory, 0700); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			namespace, err := os.Stat("/proc/thread-self/ns/net")
			if err != nil {
				t.Fatal(err)
			}
			var listener *net.UnixListener
			open := func() error {
				var err error
				listener, err = net.ListenUnix("unixpacket", &net.UnixAddr{Name: filepath.Join(directory, "g-"+strings.Repeat("a", 64)+".sock"), Net: "unixpacket"})
				if err != nil {
					t.Fatal("actual generation listener is required before testing absence", err)
				}
				return nil
			}
			defer func() {
				if listener != nil {
					listener.Close()
				}
			}()
			if !late {
				if err = open(); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			native := func(context.Context) error {
				calls++
				if late {
					return open()
				}
				return nil
			}
			if err = observeLinuxStandardServiceAbsence(ctx, root, directory, namespace, nil, func() error { return nil }, native); err == nil {
				t.Fatal("generation listener was treated as service absence")
			}
			if late && calls != 1 || !late && calls != 0 {
				t.Fatal("unexpected absence observation boundary", calls)
			}
		})
	}
}

func TestLinuxStandardServiceGenerationBusyLeaseCannotAdopt(t *testing.T) {
	root := filepath.Join(standardGenerationTestRoot(t), "root")
	directory := standardGenerationTestFiles(t, root, []byte("exact executable"), "one")
	holder, err := os.OpenFile(directory+".lock", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if err = syscall.Flock(int(holder.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	type result struct {
		generation *linuxStandardServiceGeneration
		err        error
	}
	done := make(chan result, 1)
	go func() { g, err := captureLinuxStandardServiceGeneration(ctx, root); done <- result{g, err} }()
	select {
	case r := <-done:
		if r.generation != nil || r.err == nil {
			if r.generation != nil {
				r.generation.Close()
			}
			t.Fatal("busy immutable source admitted a generation", r.err)
		}
	case <-ctx.Done():
		syscall.Flock(int(holder.Fd()), syscall.LOCK_UN)
		r := <-done
		if r.generation != nil {
			r.generation.Close()
		}
		t.Fatal("generation discovery waited beyond caller expiry for source lock")
	}
}
