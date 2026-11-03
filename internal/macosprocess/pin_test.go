package macosprocess

import (
	"os"
	"testing"
)

func TestCapturedGUISocketReadinessIsNotFilesystemPermission(t *testing.T) {
	before := pinMetadata{mode: os.ModeSocket | 0666, uid: 0, gid: 0}
	for _, mode := range []os.FileMode{0666, 0444, 0222, 0} {
		after := before
		after.mode = os.ModeSocket | mode
		if !samePinMetadata(before, after, true) {
			t.Fatal("native GUI socket readiness was treated as filesystem write access", mode)
		}
		if samePinMetadata(before, after, false) {
			t.Fatal("a named filesystem object borrowed GUI socket semantics", mode)
		}
	}
	for name, edit := range map[string]func(*pinMetadata){
		"foreign uid":     func(p *pinMetadata) { p.uid = 501 },
		"changed gid":     func(p *pinMetadata) { p.gid = 20 },
		"changed links":   func(p *pinMetadata) { p.links++ },
		"regular file":    func(p *pinMetadata) { p.mode = 0600 },
		"directory":       func(p *pinMetadata) { p.mode = os.ModeDir | 0700 },
		"pipe":            func(p *pinMetadata) { p.mode = os.ModeNamedPipe | 0600 },
		"symlink":         func(p *pinMetadata) { p.mode = os.ModeSymlink | 0600 },
		"executable bits": func(p *pinMetadata) { p.mode |= 0111 },
		"setuid":          func(p *pinMetadata) { p.mode |= os.ModeSetuid },
	} {
		t.Run(name, func(t *testing.T) {
			after := before
			edit(&after)
			if samePinMetadata(before, after, true) {
				t.Fatal("GUI descriptor accepted changed native ownership or type")
			}
		})
	}
	foreign := before
	foreign.uid = 501
	if samePinMetadata(foreign, foreign, true) {
		t.Fatal("stable foreign socket owner became privileged authority")
	}
}

func TestCapturedFilesystemPinsKeepExactOwnerAndMode(t *testing.T) {
	for _, mode := range []os.FileMode{0600, 0644, 0755, os.ModeDir | 0700, os.ModeDir | 0755} {
		before := pinMetadata{mode: mode, uid: 0, gid: 0, links: 1}
		if !samePinMetadata(before, before, false) {
			t.Fatal("valid original filesystem pin rejected", mode)
		}
		for name, edit := range map[string]func(*pinMetadata){
			"group write": func(p *pinMetadata) { p.mode |= 0020 },
			"other write": func(p *pinMetadata) { p.mode |= 0002 },
			"uid":         func(p *pinMetadata) { p.uid = 501 },
			"gid":         func(p *pinMetadata) { p.gid = 20 },
			"links":       func(p *pinMetadata) { p.links++ },
			"type":        func(p *pinMetadata) { p.mode = os.ModeSocket | 0666 },
		} {
			t.Run(mode.String()+"/"+name, func(t *testing.T) {
				after := before
				edit(&after)
				if samePinMetadata(before, after, false) {
					t.Fatal("filesystem pin lost its original ownership predicate")
				}
			})
		}
		if samePinMetadata(before, before, true) {
			t.Fatal("regular filesystem object impersonated GUI socket")
		}
	}
	for _, mode := range []os.FileMode{0666, 0620, os.ModeDir | 0775} {
		writable := pinMetadata{mode: mode, uid: 0, gid: 0, links: 1}
		if samePinMetadata(writable, writable, false) {
			t.Fatal("stable writable filesystem metadata accepted")
		}
	}
}
