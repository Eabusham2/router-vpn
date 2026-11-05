//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"strconv"
	"testing"
)

func TestDesktopLinuxSSEntryRetainsBothSourcesDNSAndRestoration(t *testing.T) {
	for _, entryMethod := range desktopSSEntryMethods {
		for _, finalMethod := range desktopSSEntryMethods {
			for _, kill := range []string{"on-connect", "always"} {
				for _, dns := range []string{"tcp", "udp"} {
					t.Run(entryMethod+"/"+finalMethod+"/"+kill+"/"+dns, func(t *testing.T) {
						profile, entry, launch := desktopSSEntryFixture(t, kill, entryMethod, finalMethod, dns)
						if !desktopLinuxExternalEligible(launch) {
							t.Fatal("original Linux SS2022 pair was not admitted")
						}
						if err := prepareDesktopExternalPhysicalCaptured(launch, "linux"); err != nil {
							t.Fatal(err)
						}
						capture, err := launch.external.physical.Capture()
						if err != nil || len(capture.PhysicalRoots) != 1 || capture.PhysicalRoots[0].Type != "shadowsocks" || capture.PhysicalRoots[0].Tag != "external-entry" || len(capture.PhysicalRoots[0].Destinations) != 2 || capture.SelectedDNS.Detour != mobilemultihop.ExternalFinalTag || capture.SelectedDNS.Physical || capture.SelectedDNS.Type != dns || capture.ConfiguredMTU != 1360 {
							t.Fatal("SS pair lost original physical root or final DNS/MTU policy", err)
						}
						for _, dest := range capture.PhysicalRoots[0].Destinations {
							if dest.Host != entry.External.Shadowsocks.Server || dest.Port != entry.External.Shadowsocks.Port || dest.Network != "tcp" && dest.Network != "udp" {
								t.Fatal("final SS acquired physical permission", dest)
							}
						}
						a := &app{profiles: common.RouterProfileStore{Profiles: []common.RouterProfile{profile, entry}}}
						h := &desktopLinuxNodeHost{launch: launch, revision: desktopOwnedNodeProfileToken(profile), externalEntryRevision: desktopOwnedNodeProfileToken(entry), savedOptions: [3]bool{profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled}, externalEntryOptions: [3]bool{entry.DAITAEnabled, entry.JumboTUN, entry.SocksEnabled}}
						if err := h.externalSourcesLocked(a); err != nil {
							t.Fatal(err)
						}
						for _, which := range []string{"entry", "final"} {
							for _, fault := range []string{"password", "method", "server", "port", "public", "id", "option"} {
								p, e := cloneRouterProfile(profile), cloneRouterProfile(entry)
								selected := &p
								if which == "entry" {
									selected = &e
								}
								mutateDesktopSSSource(selected, fault)
								a.profiles.Profiles = []common.RouterProfile{p, e}
								if h.externalSourcesLocked(a) == nil {
									t.Fatal("replaced captured SS source accepted", which, fault)
								}
							}
						}
						a.profiles.Profiles = []common.RouterProfile{profile, entry}
						if err := h.externalSourcesLocked(a); err != nil {
							t.Fatal(err)
						}
						measure, err := capturedDesktopMeasurementRuntime(launch)
						if err != nil || measure.node != profile.ID {
							t.Fatal("measurement borrowed entry identity", err)
						}
						resolver, err := capturedDesktopDNSRuntime(launch)
						if err != nil || resolver.node != profile.ID {
							t.Fatal("DNS borrowed entry identity", err)
						}
						saved := &speedLabExternalRestore{source: append([]byte(nil), launch.external.source...), profile: cloneRouterProfile(launch.external.profile), entry: cloneRouterProfile(launch.external.entry), execution: "local", root: "retained-root", network: "retained-network", mtu: 1360}
						if err := captureSpeedLabExternalRestoreSeal(saved, launch.external); err != nil {
							t.Fatal(err)
						}
						exit, err := standardExitFromExternalProfile(profile)
						if err != nil {
							t.Fatal(err)
						}
						restored, err := compileSpeedLabExternalRestore(saved, exit)
						if err != nil || !desktopLinuxExternalEligible(restored) || restored.external.session == launch.external.session || !reflect.DeepEqual(restored.external.source, launch.external.source) {
							t.Fatal("restoration lost the complete original SS pair", err)
						}
						if err := prepareDesktopExternalPhysicalCaptured(restored, "linux"); err != nil {
							t.Fatal(err)
						}
						if validateDesktopLinuxExternalSource(profile, restored, entry) != nil || restored.external.mtu == nil || restored.external.mtu.restoreMTU != 1360 {
							t.Fatal("restoration substituted original private policy or MTU")
						}
					})
				}
			}
		}
	}
}

func TestDesktopLinuxSSEntryKeepsOtherGraphsClosed(t *testing.T) {
	for _, fault := range []string{"server", "auto", "off", "entry-layer", "final-layer", "legacy-entry", "legacy-final", "connect-final", "https-final", "same-id", "predecessor"} {
		t.Run(fault, func(t *testing.T) {
			_, _, launch := desktopSSEntryFixture(t, "always", desktopSSEntryMethods[1], desktopSSEntryMethods[1], "udp")
			o := launch.external
			switch fault {
			case "server", "auto":
				o.selection = fault
			case "off":
				o.profile.KillSwitchPolicy = "off"
			case "entry-layer":
				o.entry.StartLayer = common.StartLayerAES256GCM
			case "final-layer":
				o.profile.StartLayer = common.StartLayerAES256GCM
			case "legacy-entry":
				o.entry.External.Shadowsocks.Method = "aes-256-gcm"
			case "legacy-final":
				o.profile.External.Shadowsocks.Method = "aes-256-gcm"
			case "connect-final":
				o.profile.External.Protocol = "http-connect"
				o.profile.External.HTTPConnect = &common.ExternalHTTPConnectConfig{Host: "198.51.100.240", Port: 8388, Username: "captured", Password: "captured"}
			case "https-final":
				o.profile.External.Protocol = "https-connect"
				o.profile.External.HTTPSConnect = &common.ExternalHTTPConnectConfig{Host: "198.51.100.240", Port: 8388, Username: "captured", Password: "captured", TLSServerName: "captured.example"}
			case "same-id":
				o.entry.ID = o.profile.ID
			case "predecessor":
				o.predecessor = "unrequested upstream graph"
			}
			if desktopLinuxExternalEligible(launch) {
				t.Fatal("Linux SS scope widened", fault)
			}
		})
	}
}

// Read the exact compiled declarations used by the generated producer and the
// Darwin consumer. This portable check exercises the shipping strict decoder;
// removing a consumer field must fail even though both platform sources compile.
func desktopSSEntryReceiptType(t *testing.T, path, name string) reflect.Type {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var fields []reflect.StructField
	declarations := 0
	expected := map[string][2]string{"Method": {"string", "method"}, "Address": {"string", "address"}, "PhysicalTCP": {"int64", "physical_tcp"}, "PhysicalUDP": {"int64", "physical_udp"}, "Streams": {"int64", "streams"}, "Packets": {"int64", "packets"}, "PublicReplies": {"uint32", "public_replies"}, "AuthTCP": {"uint32", "auth_tcp"}, "AuthUDP": {"uint32", "auth_udp"}}
	for _, declaration := range file.Decls {
		group, ok := declaration.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range group.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok || typeSpec.Name.Name != name {
				continue
			}
			declarations++
			structure, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				t.Fatal("receipt is not original struct")
			}
			for _, field := range structure.Fields.List {
				kind, ok := field.Type.(*ast.Ident)
				if !ok || len(field.Names) != 1 || field.Tag == nil {
					t.Fatal("receipt lost exact scalar fields")
				}
				var scalar reflect.Type
				switch kind.Name {
				case "string":
					scalar = reflect.TypeOf("")
				case "int64":
					scalar = reflect.TypeOf(int64(0))
				case "uint32":
					scalar = reflect.TypeOf(uint32(0))
				default:
					t.Fatal("unexpected receipt field type")
				}
				tag, err := strconv.Unquote(field.Tag.Value)
				if err != nil {
					t.Fatal(err)
				}
				shape, exists := expected[field.Names[0].Name]
				if !exists || kind.Name != shape[0] || tag != `json:"`+shape[1]+`"` {
					t.Fatal("receipt field type or exact JSON tag changed")
				}
				fields = append(fields, reflect.StructField{Name: field.Names[0].Name, Type: scalar, Tag: reflect.StructTag(tag)})
			}
		}
	}
	if len(fields) == 0 || declarations != 1 {
		t.Fatal("original receipt declaration absent")
	}
	return reflect.StructOf(fields)
}

func TestDesktopLinuxSSEntryDarwinReceiptUsesExactSchema(t *testing.T) {
	producer := desktopSSEntryReceiptType(t, "../../mobile/desktop/node_external_ss_entry_test.go.tmpl", "desktopExternalInstalledSSReceipt")
	consumer := desktopSSEntryReceiptType(t, "desktop_external_ss_entry_darwin_native_test.go", "macOSExternalSSEntryReceipt")
	for _, live := range []bool{false, true} {
		value := reflect.New(producer).Elem()
		value.FieldByName("Method").SetString("2022-blake3-aes-256-gcm")
		value.FieldByName("Address").SetString("11.77.0.2:8388")
		if live {
			value.FieldByName("AuthTCP").SetUint(3)
			value.FieldByName("AuthUDP").SetUint(4)
		}
		raw, err := json.Marshal(value.Interface())
		if err != nil {
			t.Fatal(err)
		}
		decoded := reflect.New(consumer)
		if err := decodeRelayControlJSON(raw, decoded.Interface()); err != nil {
			t.Fatal("actual Darwin SS receipt rejected original producer schema", err)
		}
		for _, field := range []string{"AuthTCP", "AuthUDP"} {
			if decoded.Elem().FieldByName(field).Uint() != value.FieldByName(field).Uint() {
				t.Fatal("Darwin receipt replaced original authentication count")
			}
		}
		for _, extra := range []string{`,"foreign":1}`, `,"auth_tcp":3}`} {
			changed := append(append([]byte{}, raw[:len(raw)-1]...), []byte(extra)...)
			if decodeRelayControlJSON(changed, reflect.New(consumer).Interface()) == nil {
				t.Fatal("Darwin receipt admitted unknown or duplicated authentication source")
			}
		}
		negative := bytes.Replace(raw, []byte(`"auth_tcp":0`), []byte(`"auth_tcp":-1`), 1)
		if !live && decodeRelayControlJSON(negative, reflect.New(consumer).Interface()) == nil {
			t.Fatal("Darwin receipt admitted negative authentication count")
		}
	}
}
