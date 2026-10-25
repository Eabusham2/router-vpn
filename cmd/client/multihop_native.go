package main

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	nativeMultihopMaxFile        = int64(8 << 20)
	nativeMultihopMaxTotal       = int64(32 << 20)
	nativeMultihopEntryProofPort = 1098
	nativeMultihopExitProofPort  = 1099
)

var nativeMultihopID = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

type nativeWG struct {
	PrivateKey, PublicKey, PSK, Host string
	Addresses, AllowedIPs            []string
	Port, MTU                        int
}

func nativeGeneratedDir(root, id, mode string) (string, error) {
	if !nativeMultihopID.MatchString(id) || !nativeMultihopID.MatchString(mode) {
		return "", errors.New("unsafe multihop node or mode id")
	}
	baseRoot, err := canonicalBundleRoot(root)
	if err != nil {
		return "", err
	}
	base := filepath.Join(baseRoot, "generated")
	if err := ensurePrivateDirectoryNoSymlink(base); err != nil {
		return "", err
	}
	candidate := filepath.Clean(filepath.Join(base, id, mode))
	rel, err := filepath.Rel(base, candidate)
	if err != nil || rel == "." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		return "", errors.New("multihop profile escaped generated root")
	}
	return candidate, nil
}

func parseNativeWG(path string) (nativeWG, error) {
	raw, err := readPrivateRegular(path, 1<<20)
	if err != nil {
		return nativeWG{}, fmt.Errorf("entry WireGuard profile: %w", err)
	}
	section := ""
	iface := map[string]string{}
	peer := map[string]string{}
	peers := 0
	s := bufio.NewScanner(strings.NewReader(string(raw)))
	for s.Scan() {
		line := strings.TrimSpace(strings.SplitN(s.Text(), "#", 2)[0])
		if line == "" {
			continue
		}
		if strings.EqualFold(line, "[Interface]") {
			section = "interface"
			continue
		}
		if strings.EqualFold(line, "[Peer]") {
			peers++
			section = "peer"
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, value := strings.ToLower(strings.TrimSpace(parts[0])), strings.TrimSpace(parts[1])
		if section == "interface" {
			iface[key] = value
		} else if section == "peer" {
			peer[key] = value
		}
	}
	if err := s.Err(); err != nil {
		return nativeWG{}, err
	}
	if peers != 1 {
		return nativeWG{}, errors.New("desktop multihop entry requires exactly one standard WireGuard peer")
	}
	req := func(m map[string]string, key, msg string) (string, error) {
		v := strings.TrimSpace(m[key])
		if v == "" {
			return "", errors.New(msg)
		}
		return v, nil
	}
	privateKey, err := req(iface, "privatekey", "entry WireGuard private key is missing")
	if err != nil {
		return nativeWG{}, err
	}
	address, err := req(iface, "address", "entry WireGuard address is missing")
	if err != nil {
		return nativeWG{}, err
	}
	publicKey, err := req(peer, "publickey", "entry WireGuard peer public key is missing")
	if err != nil {
		return nativeWG{}, err
	}
	allowed, err := req(peer, "allowedips", "entry WireGuard AllowedIPs are missing")
	if err != nil {
		return nativeWG{}, err
	}
	endpoint, err := req(peer, "endpoint", "entry WireGuard endpoint is missing")
	if err != nil {
		return nativeWG{}, err
	}
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil {
		host, portText, err = net.SplitHostPort(strings.TrimSpace(endpoint))
		if err != nil {
			return nativeWG{}, errors.New("entry WireGuard endpoint is invalid")
		}
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nativeWG{}, errors.New("entry WireGuard endpoint port is invalid")
	}
	split := func(v string) []string {
		out := []string{}
		for _, x := range strings.Split(v, ",") {
			x = strings.TrimSpace(x)
			if x != "" {
				out = append(out, x)
			}
		}
		return out
	}
	wg := nativeWG{PrivateKey: privateKey, PublicKey: publicKey, PSK: strings.TrimSpace(peer["presharedkey"]), Host: strings.Trim(host, "[]"), Addresses: split(address), AllowedIPs: split(allowed), Port: port}
	if len(wg.Addresses) == 0 || len(wg.AllowedIPs) == 0 {
		return nativeWG{}, errors.New("entry WireGuard address/AllowedIPs are empty")
	}
	if rawMTU := strings.TrimSpace(iface["mtu"]); rawMTU != "" {
		wg.MTU, err = strconv.Atoi(rawMTU)
		if err != nil || wg.MTU < 1280 || wg.MTU > 9000 {
			return nativeWG{}, errors.New("entry WireGuard MTU is invalid")
		}
	}
	return wg, nil
}

func copyNativeMultihopTree(src, dst string) error {
	if err := ensurePrivateRuntimeDirectory(dst); err != nil {
		return err
	}
	var total int64
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("multihop profile contains symlink: %s", d.Name())
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		out := filepath.Join(dst, rel)
		if d.IsDir() {
			return ensurePrivateRuntimeDirectory(out)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("multihop profile contains non-regular file: %s", rel)
		}
		if info.Size() > nativeMultihopMaxFile {
			return fmt.Errorf("multihop profile file too large: %s", rel)
		}
		body, err := readPrivateRegular(path, nativeMultihopMaxFile)
		if err != nil {
			return fmt.Errorf("read private multihop profile %s: %w", rel, err)
		}
		total += int64(len(body))
		if total > nativeMultihopMaxTotal {
			return errors.New("multihop private runtime exceeds staging limit")
		}
		return writePrivateRuntimeFile(out, body)
	})
}

func nativeWGEndpoint(wg nativeWG) map[string]any {
	peer := map[string]any{"address": wg.Host, "port": wg.Port, "public_key": wg.PublicKey, "allowed_ips": wg.AllowedIPs}
	if wg.PSK != "" {
		peer["pre_shared_key"] = wg.PSK
	}
	endpoint := map[string]any{"type": "wireguard", "tag": "entry-wg", "address": wg.Addresses, "private_key": wg.PrivateKey, "peers": []any{peer}}
	if wg.MTU != 0 {
		endpoint["mtu"] = wg.MTU
	}
	return endpoint
}

func nativeEntryPrivateOutbound(host string, port int, username, password string) (map[string]any, error) {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if net.ParseIP(host) == nil {
		return nil, errors.New("native multihop entry private SOCKS host must be a literal IP address")
	}
	if port == 0 {
		port = 1080
	}
	if port < 1 || port > 65535 {
		return nil, errors.New("native multihop entry private SOCKS port is invalid")
	}
	username = strings.TrimSpace(username)
	if (username == "") != (password == "") {
		return nil, errors.New("native multihop entry private SOCKS credentials are incomplete")
	}
	out := map[string]any{
		"type": "socks", "tag": "entry-private", "server": host,
		"server_port": port, "version": "5", "detour": "entry-wg",
	}
	if username != "" {
		out["username"] = username
		out["password"] = password
	}
	return out, nil
}

func prepareNativeMultihop(root string, sel multihopSelection) (string, string, error) {
	return stageNativeMultihopCapture(root, sel)
}

func nativeWindowsMultihopCommand(a *app, sel multihopSelection) (*desktopNodeLaunch, error) {
	return prepareOwnedNativeMultihopCommand(a, sel, nil)
}
