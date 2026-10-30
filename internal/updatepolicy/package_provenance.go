package updatepolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

const MaxPackageProvenanceBytes = 64 << 10

// PackageProvenance is the exact four-field schema written into native
// packages by deploy/source_provenance.py. Parsing proves the public record;
// the caller still owns the package file and its filesystem trust boundary.
type PackageProvenance struct {
	SchemaVersion  int    `json:"schema_version"`
	Repository     string `json:"repository"`
	SourceSHA      string `json:"source_sha"`
	ArtifactFamily string `json:"artifact_family"`
}

func ParsePackageProvenance(raw []byte) (PackageProvenance, error) {
	var result PackageProvenance
	if len(raw) == 0 || len(raw) > MaxPackageProvenanceBytes {
		return result, errors.New("package provenance is empty or exceeds its bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return result, errors.New("package provenance requires one object")
	}
	seen := make(map[string]bool, 4)
	for decoder.More() {
		name, err := decoder.Token()
		key, ok := name.(string)
		if err != nil || !ok || seen[key] {
			return PackageProvenance{}, errors.New("package provenance repeats or corrupts a field")
		}
		seen[key] = true
		var destination any
		switch key {
		case "schema_version":
			destination = &result.SchemaVersion
		case "repository":
			destination = &result.Repository
		case "source_sha":
			destination = &result.SourceSHA
		case "artifact_family":
			destination = &result.ArtifactFamily
		default:
			return PackageProvenance{}, errors.New("package provenance contains an unknown field")
		}
		if err := decoder.Decode(destination); err != nil {
			return PackageProvenance{}, errors.New("package provenance field has an invalid type")
		}
	}
	end, err := decoder.Token()
	var extra any
	if err != nil || end != json.Delim('}') || decoder.Decode(&extra) != io.EOF || len(seen) != 4 {
		return PackageProvenance{}, errors.New("package provenance has missing or trailing content")
	}
	if result.SchemaVersion != 1 || result.Repository != "Eabusham2/router-vpn" || !isHex(result.SourceSHA, 40) ||
		len(result.ArtifactFamily) == 0 || len(result.ArtifactFamily) > 64 {
		return PackageProvenance{}, errors.New("package provenance identity is invalid")
	}
	// isHex also accepts uppercase for signed-manifest compatibility. Embedded
	// native provenance is canonical lowercase, as its actual writer requires.
	for _, value := range result.SourceSHA {
		if !(value >= '0' && value <= '9' || value >= 'a' && value <= 'f') {
			return PackageProvenance{}, errors.New("package source SHA is not canonical")
		}
	}
	for _, value := range result.ArtifactFamily {
		if !(value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' || value >= '0' && value <= '9' || value == '.' || value == '_' || value == '-') {
			return PackageProvenance{}, errors.New("package provenance artifact family is invalid")
		}
	}
	return result, nil
}
