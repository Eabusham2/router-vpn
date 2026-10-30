package updatepolicy

import (
	"strings"
	"testing"
)

func TestPackageProvenanceActualNativeWriterShape(t *testing.T) {
	for _, family := range []string{"windows-amd64", "windows-arm64", "windows-portable-amd64", "windows-portable-arm64", "darwin-arm64", "linux-amd64", "freebsd-amd64"} {
		raw := "{\n  \"artifact_family\": \"" + family + "\",\n  \"repository\": \"Eabusham2/router-vpn\",\n  \"schema_version\": 1,\n  \"source_sha\": \"" + strings.Repeat("a", 40) + "\"\n}\n"
		got, err := ParsePackageProvenance([]byte(raw))
		if err != nil || got.SchemaVersion != 1 || got.Repository != "Eabusham2/router-vpn" || got.SourceSHA != strings.Repeat("a", 40) || got.ArtifactFamily != family {
			t.Fatalf("actual %s package writer shape was rejected: %+v %v", family, got, err)
		}
	}
}

func TestPackageProvenanceRejectsAmbiguousIdentity(t *testing.T) {
	valid := `{"schema_version":1,"repository":"Eabusham2/router-vpn","source_sha":"` + strings.Repeat("c", 40) + `","artifact_family":"windows-amd64"}`
	for name, raw := range map[string]string{
		"legacy missing schema": `{"repository":"Eabusham2/router-vpn","source_sha":"` + strings.Repeat("c", 40) + `"}`,
		"unknown":               strings.Replace(valid, `"schema_version":1`, `"schema_version":1,"unexpected":true`, 1),
		"duplicate":             strings.Replace(valid, `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1),
		"case alias":            strings.Replace(valid, `"source_sha"`, `"Source_SHA"`, 1),
		"schema null":           strings.Replace(valid, `"schema_version":1`, `"schema_version":null`, 1),
		"schema string":         strings.Replace(valid, `"schema_version":1`, `"schema_version":"1"`, 1),
		"future schema":         strings.Replace(valid, `"schema_version":1`, `"schema_version":2`, 1),
		"wrong repository":      strings.Replace(valid, "Eabusham2/router-vpn", "foreign/router-vpn", 1),
		"uppercase SHA":         strings.Replace(valid, strings.Repeat("c", 40), strings.Repeat("C", 40), 1),
		"short SHA":             strings.Replace(valid, strings.Repeat("c", 40), strings.Repeat("c", 39), 1),
		"empty family":          strings.Replace(valid, "windows-amd64", "", 1),
		"path family":           strings.Replace(valid, "windows-amd64", "windows/amd64", 1),
		"null family":           strings.Replace(valid, `"artifact_family":"windows-amd64"`, `"artifact_family":null`, 1),
		"trailing":              valid + "{}",
		"oversized":             valid + strings.Repeat(" ", MaxPackageProvenanceBytes),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePackageProvenance([]byte(raw)); err == nil {
				t.Fatal("invalid packaged provenance was accepted")
			}
		})
	}
}
