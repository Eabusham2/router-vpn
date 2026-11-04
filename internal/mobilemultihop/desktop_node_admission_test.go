package mobilemultihop

import "testing"

func TestDesktopCompleteMAXAdmissionKeepsItsNativePlatformBoundary(t *testing.T) {
	for _, mode := range []string{"max-quic-wg", "max-quic-awg", "max-tls-wg", "max-tls-awg"} {
		t.Run(mode, func(t *testing.T) {
			for _, layer := range []string{"", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
				if !DesktopNodePhysicalGraphSupported(mode, layer) {
					t.Fatal("Windows complete MAX lost its admitted native composition", mode, layer)
				}
				if DesktopLinuxNodePhysicalGraphSupported(mode, layer) {
					t.Fatal("Windows admission opened an unproved Linux host composition", mode, layer)
				}
			}
			for _, layer := range []string{"xor", "aes-128-gcm", "aes-256-gcm+xor", "uncaptured-layer"} {
				if DesktopNodePhysicalGraphSupported(mode, layer) {
					t.Fatal("complete MAX admitted an uncaptured Start Layer", mode, layer)
				}
			}
		})
	}
	for _, mode := range []string{"MAX-TLS-WG", "max-tls", "max-quic", "max-tls-openvpn", "foreign-max"} {
		if DesktopNodePhysicalGraphSupported(mode, "off") {
			t.Fatal("complete MAX admission widened to another graph", mode)
		}
	}
}
