//go:build darwin || linux

package main

import (
	"bytes"
	"encoding/binary"
	"slices"
	"strings"
	"testing"
)

func macPythonTestPathCommand(kind uint32, value string) []byte {
	header := 12
	if kind == 0xc || kind == 0x80000018 || kind == 0x8000001f || kind == 0x20 || kind == 0x80000023 {
		header = 24
	}
	length := (header + len(value) + 1 + 7) &^ 7
	command := make([]byte, length)
	binary.LittleEndian.PutUint32(command, kind)
	binary.LittleEndian.PutUint32(command[4:], uint32(length))
	binary.LittleEndian.PutUint32(command[8:], uint32(header))
	copy(command[header:], value)
	return command
}

func macPythonTestImage(cpu, kind uint32, commands ...[]byte) []byte {
	if len(commands) == 0 {
		command := make([]byte, 24)
		binary.LittleEndian.PutUint32(command, 0x1b) // LC_UUID
		binary.LittleEndian.PutUint32(command[4:], 24)
		commands = [][]byte{command}
	}
	loads := bytes.Join(commands, nil)
	image := make([]byte, 32+len(loads))
	binary.LittleEndian.PutUint32(image, 0xfeedfacf)
	binary.LittleEndian.PutUint32(image[4:], cpu)
	binary.LittleEndian.PutUint32(image[12:], kind)
	binary.LittleEndian.PutUint32(image[16:], uint32(len(commands)))
	binary.LittleEndian.PutUint32(image[20:], uint32(len(loads)))
	copy(image[32:], loads)
	return image
}

func macPythonTestUniversal(images ...[]byte) []byte {
	header := 8 + 20*len(images)
	value := make([]byte, header)
	binary.BigEndian.PutUint32(value, 0xcafebabe)
	binary.BigEndian.PutUint32(value[4:], uint32(len(images)))
	for index, image := range images {
		offset := len(value)
		entry := value[8+20*index : 8+20*(index+1)]
		binary.BigEndian.PutUint32(entry, binary.LittleEndian.Uint32(image[4:]))
		binary.BigEndian.PutUint32(entry[4:], binary.LittleEndian.Uint32(image[8:]))
		binary.BigEndian.PutUint32(entry[8:], uint32(offset))
		binary.BigEndian.PutUint32(entry[12:], uint32(len(image)))
		value = append(value, image...)
	}
	return value
}

func TestMacPythonStaticLoadCapture(t *testing.T) {
	var commands [][]byte
	for _, kind := range []uint32{0xc, 0x80000018, 0x8000001f, 0x20, 0x80000023} {
		commands = append(commands, macPythonTestPathCommand(kind, "/owned/lib/runtime.dylib"))
	}
	commands = append(commands, macPythonTestPathCommand(0x8000001c, "@executable_path/../Frameworks"))
	commands = append(commands, macPythonTestPathCommand(0xe, "/usr/lib/dyld"))
	intel, arm := macPythonTestImage(0x01000007, 2, commands...), macPythonTestImage(0x0100000c, 2, commands...)
	for _, image := range [][]byte{intel, macPythonTestUniversal(intel, arm)} {
		images, recognized, err := macPythonMachO(bytes.NewReader(image), int64(len(image)))
		if err != nil || !recognized || len(images) < 1 {
			t.Fatal("actual static native image was not captured", err)
		}
		for _, slice := range images {
			if len(slice.loads) != 5 || !slice.loads[1].weak || !slices.Equal(slice.rpaths, []string{"@executable_path/../Frameworks"}) {
				t.Fatal("a weak/lazy/reexport/upward or rpath load was omitted", slice)
			}
		}
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"command-count": func(value []byte) []byte { binary.LittleEndian.PutUint32(value[16:], 5000); return value },
		"command-bound": func(value []byte) []byte {
			binary.LittleEndian.PutUint32(value[20:], macPythonMetadataLimit+1)
			return value
		},
		"path-offset": func(value []byte) []byte { binary.LittleEndian.PutUint32(value[40:], 4); return value },
		"path-terminator": func(value []byte) []byte {
			for i := 32 + 24; i < 32+int(binary.LittleEndian.Uint32(value[36:])); i++ {
				value[i] = 'x'
			}
			return value
		},
		"command-extent": func(value []byte) []byte {
			binary.LittleEndian.PutUint32(value[36:], uint32(len(value)+8))
			return value
		},
		"unknown-required":     func(value []byte) []byte { binary.LittleEndian.PutUint32(value[32:], 0x8000ff00); return value },
		"embedded-environment": func(value []byte) []byte { binary.LittleEndian.PutUint32(value[32:], 0x27); return value },
		"foreign-loader": func(value []byte) []byte {
			return macPythonTestImage(0x01000007, 2, macPythonTestPathCommand(0xe, "/owned/dyld"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			image := mutate(bytes.Clone(intel))
			if _, _, err := macPythonMachO(bytes.NewReader(image), int64(len(image))); err == nil {
				t.Fatal("malformed native loader metadata received runtime authority", name)
			}
		})
	}
	for _, defect := range []string{"overlap", "duplicate", "identity", "extent"} {
		t.Run("universal-"+defect, func(t *testing.T) {
			image := macPythonTestUniversal(intel, arm)
			switch defect {
			case "overlap":
				copy(image[36:40], image[16:20])
			case "duplicate":
				copy(image[28:36], image[8:16])
			case "identity":
				binary.BigEndian.PutUint32(image[28:], 0x01000007)
				binary.BigEndian.PutUint32(image[32:], 1)
			case "extent":
				binary.BigEndian.PutUint32(image[20:], uint32(len(image)))
			}
			if _, _, err := macPythonMachO(bytes.NewReader(image), int64(len(image))); err == nil {
				t.Fatal("ambiguous universal metadata received runtime authority", defect)
			}
		})
	}
}

func TestMacPythonEnvironmentAndLoaderPaths(t *testing.T) {
	t.Setenv("PYTHONPATH", "/untrusted")
	t.Setenv("DYLD_INSERT_LIBRARIES", "/untrusted/library.dylib")
	environment := strings.Join(macOSPythonEnvironment(), "\n")
	if strings.Contains(environment, "/untrusted") || !strings.Contains(environment, "DYLD_FALLBACK_LIBRARY_PATH=/usr/lib\n") || !strings.Contains(environment, "DYLD_FALLBACK_FRAMEWORK_PATH=/System/Library/Frameworks") {
		t.Fatal("privileged Python retained ambient or foreign fallback authority", environment)
	}
	for _, value := range []string{"library.dylib", "@unknown/library", "@rpath/library", "relative/../library"} {
		if _, err := macPythonExpand(value, "/owned/lib/module.so", "/owned/bin/python3"); err == nil {
			t.Fatal("unbound path expanded with ambient authority", value)
		}
	}
	value, err := macPythonExpand("@loader_path/alias/../lib.dylib", "/owned/lib/module.so", "/owned/bin/python3")
	if err != nil || value != "/owned/lib/alias/../lib.dylib" {
		t.Fatal("lexical loader expansion erased a real symlink traversal", value, err)
	}
}
