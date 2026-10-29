package mobiletor

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func desktopPFLegacyFixtureChildren(next func(string) ([]byte, error)) func(string) ([]byte, error) {
	return func(anchor string) ([]byte, error) {
		parents := map[string]string{"": "com.apple\n", "com.apple": "000.router-vpn\n", "com.apple/000.router-vpn": "physical\n"}
		if value, exists := parents[anchor]; exists {
			return []byte(value), nil
		}
		return next(anchor)
	}
}

func TestDesktopDarwinPFLegacyInventoryReadsUnreferencedChildren(t *testing.T) {
	root := "com.apple/000.router-vpn/physical"
	for _, retained := range []bool{false, true} {
		t.Run(fmt.Sprint(retained), func(t *testing.T) {
			var reads []string
			children := map[string]string{root: "  " + root + "/previous\n", root + "/previous": "generation\n"}
			err := desktopPFRejectLegacyRules(root, func(anchor string) (string, error) {
				reads = append(reads, anchor)
				if anchor == root+"/previous/generation" && retained {
					return "block out on lo0 all", nil
				}
				return "", nil
			}, desktopPFLegacyFixtureChildren(func(anchor string) ([]byte, error) { return []byte(children[anchor]), nil }))
			if retained && (err == nil || !strings.Contains(err.Error(), "earlier nested physical owner")) || !retained && err != nil {
				t.Fatal("unreferenced legacy rules escaped direct owner rejection", retained, err)
			}
			if !reflect.DeepEqual(reads, []string{root, root + "/previous", root + "/previous/generation"}) {
				t.Fatal("legacy inventory did not directly inspect every exact child", reads)
			}
		})
	}
}

func TestDesktopDarwinPFInventoryRejectsEscapingOrAmbiguousChildren(t *testing.T) {
	root := "com.apple/000.router-vpn/physical"
	for _, raw := range []string{"../other", "other/child", "/foreign/child", root, root + "/child/deeper", ".", "..", "*", "child\nchild", "child\n" + root + "/child", "child with spaces", strings.Repeat("x", 64<<10+1)} {
		if value, err := desktopPFInventoryChildren(root, []byte(raw)); err == nil || value != nil {
			t.Fatal("ambiguous or escaping PF child inventory was accepted")
		}
	}
	for _, root := range []string{"/absolute", "a/../b", "a//b", strings.Repeat("a", 1024)} {
		if _, err := desktopPFInventoryChildren(root, nil); err == nil {
			t.Fatal("uncaptured inventory parent was accepted")
		}
	}
}

func TestDesktopDarwinPFLegacyInventoryBoundsAndReadErrors(t *testing.T) {
	root := "com.apple/000.router-vpn/physical"
	read := func(string) (string, error) { return "", nil }
	for _, width := range []int{256, 257} {
		var children strings.Builder
		for i := 0; i < width; i++ {
			fmt.Fprintf(&children, "child%d\n", i)
		}
		err := desktopPFRejectLegacyRules(root, read, desktopPFLegacyFixtureChildren(func(anchor string) ([]byte, error) {
			if anchor != root {
				t.Fatal("over-wide legacy inventory performed a child query")
			}
			return []byte(children.String()), nil
		}))
		if err == nil {
			t.Fatal("unbounded legacy PF inventory was accepted")
		}
	}
	queries := 0
	if err := desktopPFRejectLegacyRules(root, read, desktopPFLegacyFixtureChildren(func(string) ([]byte, error) {
		queries++
		return []byte("child\n"), nil
	})); err == nil || queries != 9 {
		t.Fatal("recursive legacy PF inventory lost its depth bound", queries, err)
	}
	want := errors.New("exact native read failure")
	if err := desktopPFRejectLegacyRules(root, func(string) (string, error) { return "", want }, desktopPFLegacyFixtureChildren(func(string) ([]byte, error) {
		t.Fatal("failed rules query was treated as empty")
		return nil, nil
	})); !errors.Is(err, want) {
		t.Fatal("legacy rules read failure was hidden", err)
	}
	if err := desktopPFRejectLegacyRules(root, read, func(string) ([]byte, error) { return nil, want }); !errors.Is(err, want) {
		t.Fatal("legacy child read failure was hidden", err)
	}
}

func TestDesktopDarwinPFLegacyAbsenceUsesExistingParentInventory(t *testing.T) {
	root := "com.apple/000.router-vpn/physical"
	for _, missing := range []string{"com.apple", "com.apple/000.router-vpn", root} {
		var queries []string
		read := desktopPFLegacyFixtureChildren(func(string) ([]byte, error) {
			t.Fatal("missing legacy root was queried as an existing anchor")
			return nil, nil
		})
		err := desktopPFRejectLegacyRules(root, func(string) (string, error) {
			t.Fatal("missing legacy root was read without proving its existence")
			return "", nil
		}, func(anchor string) ([]byte, error) {
			queries = append(queries, anchor)
			parent := ""
			if at := strings.LastIndexByte(missing, '/'); at >= 0 {
				parent = missing[:at]
			}
			if anchor == parent {
				return nil, nil
			}
			return read(anchor)
		})
		if err != nil || len(queries) != strings.Count(missing, "/")+1 {
			t.Fatal("legacy absence lost its exact existing parent readback", missing, queries, err)
		}
	}
}
