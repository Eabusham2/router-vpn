package mobilemultihop

import (
	"reflect"
	"testing"
)

func TestImportedDesktopPhysicalCaptureRetainsExactSourceAndRetires(t *testing.T) {
	source, capture, files, profile := importedEntryFixture(t, "", "")
	c, err := NewImportedEntry(source, capture, "shadowsocks", files, profile, "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	original := c.Config()
	first, err := c.ImportedPhysicalEgress()
	if err != nil || len(first) != 2 {
		t.Fatal("actual TCP/UDP entry sockets not captured", first, err)
	}
	again, err := c.ImportedPhysicalEgress()
	if err != nil || !reflect.DeepEqual(first, again) || c.Config() != original {
		t.Fatal("projection changed executable source", err)
	}
	first[0].Port = 1
	if first[0].Port == again[0].Port {
		t.Fatal("projection exposed mutable socket authority")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ImportedPhysicalEgress(); err == nil {
		t.Fatal("closed graph retained physical authority")
	}
}
