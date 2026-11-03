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
		if !samePinMetadata(before, after, true, false) {
			t.Fatal("native GUI socket readiness was treated as filesystem write access", mode)
		}
		if samePinMetadata(before, after, false, false) {
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
			if samePinMetadata(before, after, true, false) {
				t.Fatal("GUI descriptor accepted changed native ownership or type")
			}
		})
	}
	foreign := before
	foreign.uid = 501
	if samePinMetadata(foreign, foreign, true, false) {
		t.Fatal("stable foreign socket owner became privileged authority")
	}
}

func TestCapturedFilesystemPinsKeepExactOwnerAndMode(t *testing.T) {
	for _, mode := range []os.FileMode{0600, 0644, 0755, os.ModeDir | 0700, os.ModeDir | 0755} {
		before := pinMetadata{mode: mode, uid: 0, gid: 0, links: 1}
		if !samePinMetadata(before, before, false, mode.IsDir()) {
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
				if name == "links" && mode.IsDir() {
					after.links = 0
				}
				if samePinMetadata(before, after, false, mode.IsDir()) {
					t.Fatal("filesystem pin lost its original ownership predicate")
				}
			})
		}
		if samePinMetadata(before, before, true, false) {
			t.Fatal("regular filesystem object impersonated GUI socket")
		}
	}
	for _, mode := range []os.FileMode{0666, 0620, os.ModeDir | 0775} {
		writable := pinMetadata{mode: mode, uid: 0, gid: 0, links: 1}
		if samePinMetadata(writable, writable, false, mode.IsDir()) {
			t.Fatal("stable writable filesystem metadata accepted")
		}
	}
}

func TestCapturedDirectoryEntryCountChangesPreserveOriginalIdentityClass(t *testing.T) {
	before := pinMetadata{mode: os.ModeDir | 0700, uid: 0, gid: 0, links: 5}
	for _, links := range []uint64{1, 2, 4, 5, 6, 32} {
		after := before
		after.links = links
		if !samePinMetadata(before, after, false, true) {
			t.Fatal("owned directory child change was mistaken for a regular-file hard link", links)
		}
		if samePinMetadata(before, after, false, false) || samePinMetadata(before, after, true, true) {
			t.Fatal("directory count semantics escaped their explicit filesystem class")
		}
	}
	for name, edit := range map[string]func(*pinMetadata){
		"unlinked":             func(p *pinMetadata) { p.links = 0 },
		"foreign uid":          func(p *pinMetadata) { p.uid = 501 },
		"changed gid":          func(p *pinMetadata) { p.gid = 20 },
		"group write":          func(p *pinMetadata) { p.mode |= 0020 },
		"other write":          func(p *pinMetadata) { p.mode |= 0002 },
		"changed private mode": func(p *pinMetadata) { p.mode = os.ModeDir | 0755 },
		"regular file":         func(p *pinMetadata) { p.mode = 0600 },
		"socket":               func(p *pinMetadata) { p.mode = os.ModeSocket | 0666 },
		"symlink":              func(p *pinMetadata) { p.mode = os.ModeSymlink | 0700 },
		"mixed native type":    func(p *pinMetadata) { p.mode |= os.ModeSocket },
	} {
		t.Run(name, func(t *testing.T) {
			after := before
			edit(&after)
			if samePinMetadata(before, after, false, true) {
				t.Fatal("directory lost its original linked ownership/type/permissions")
			}
		})
	}
	unlinked := before
	unlinked.links = 0
	if samePinMetadata(unlinked, before, false, true) {
		t.Fatal("an initially unlinked directory became captured authority")
	}
	regular := pinMetadata{mode: 0600, uid: 0, gid: 0, links: 1}
	linked := regular
	linked.links = 2
	for _, directory := range []bool{false, true} {
		if samePinMetadata(regular, linked, false, directory) {
			t.Fatal("regular input borrowed directory count semantics")
		}
	}
}
