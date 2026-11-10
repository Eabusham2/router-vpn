package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDesktopImportedNaiveH2LiteralHomeGraphs(t *testing.T) {
	for _, kind := range []string{"http-connect", "https-connect"} {
		t.Run(kind, func(t *testing.T) {
			root, original := desktopImportedNaiveH2Fixture(t, kind, "off", "off")
			original.Exit.DNSProtocol, original.Exit.DNSPort = "", 0
			original.Control = cloneRouterProfile(original.Exit)
			before := string(mustImportedJSON(t, original))
			selected, err := captureNativeMultihopSelection(context.Background(), root, original, []string{original.ExitMode}, nil)
			if err != nil {
				t.Fatal(err)
			}
			launch, err := compileRetainedNativeMultihopLaunch(selected, nil)
			if err != nil {
				t.Fatal(err)
			}
			graph := retainedGraph(t, launch.config)
			servers := graph["dns"].(map[string]any)["servers"].([]any)
			if len(servers) != 2 {
				t.Fatal("Home graph lost selected and retained lower resolver")
			}
			dns, lower := servers[0].(map[string]any), servers[1].(map[string]any)
			if dns["type"] != "udp" || dns["server"] != original.Exit.AdGuardIPv4 || dns["server_port"] != float64(53) || dns["detour"] != "proxy" || lower["type"] != dns["type"] || lower["server"] != dns["server"] || lower["server_port"] != dns["server_port"] || lower["detour"] != "entry-wg" || before != string(mustImportedJSON(t, original)) {
				t.Fatal("Home graph changed source or resolver ownership")
			}
			if len(launch.nodePhysicalEgress) != 1 {
				t.Fatal("Home graph lost exact CONNECT physical owner")
			}
			for _, tuple := range launch.nodePhysicalEgress {
				if tuple.Host != original.Entry.Endpoint || tuple.Network != "tcp" {
					t.Fatal("Home graph granted unowned physical transport", tuple)
				}
			}
			if directory := os.Getenv("ROUTERVPN_DESKTOP_NAIVE_H2_HOME_GRAPHS"); directory != "" {
				file, err := os.OpenFile(filepath.Join(directory, kind+".json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				_, writeErr := file.Write(launch.config)
				closeErr := file.Close()
				if writeErr != nil || closeErr != nil {
					t.Fatal(writeErr, closeErr)
				}
			}
		})
	}
}
