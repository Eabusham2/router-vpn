package mobilemultihop

import (
	"encoding/json"
	"sync"
)

// Wire limits include each complete JSON object. In-process callers retain
// the original full metadata for source comparison and selected target lookup.
const (
	nodeChainCandidateLegacyMetadataBytes = 24 << 10
	nodeChainCandidatePageBytes           = 12 << 10
)

type nodeChainCandidateMetadataCache struct {
	mu     sync.Mutex
	full   string
	values map[string]*nodeChainCandidateMetadataPages
}

type nodeChainCandidateMetadataPages struct {
	legacy  string
	header  map[string]json.RawMessage
	targets []json.RawMessage
	index   map[string]int
}

func compileNodeChainCandidateMetadataPages(raw string) *nodeChainCandidateMetadataPages {
	if raw == "" || len(raw) > NodeChainInputLimit {
		return nil
	}
	if len(raw) <= nodeChainCandidateLegacyMetadataBytes {
		return &nodeChainCandidateMetadataPages{legacy: raw}
	}
	var header map[string]json.RawMessage
	var members []struct {
		ID     string `json:"id"`
		Source string `json:"source_sha256"`
	}
	if json.Unmarshal([]byte(raw), &header) != nil || string(header["schema"]) != "1" ||
		json.Unmarshal(header["targets"], &members) != nil || len(members) == 0 {
		return nil
	}
	result := &nodeChainCandidateMetadataPages{header: header, targets: make([]json.RawMessage, len(members)), index: make(map[string]int, len(members))}
	for i, target := range members {
		if target.ID == "" || target.Source == "" {
			return nil
		}
		if _, exists := result.index[target.ID]; exists {
			return nil
		}
		result.index[target.ID] = i
		result.targets[i], _ = json.Marshal(target)
	}
	canonical, _ := json.Marshal(result.targets)
	header["schema"] = json.RawMessage("2")
	header["target_total"], _ = json.Marshal(len(members))
	header["targets_sha256"], _ = json.Marshal(externalDigest(canonical))
	delete(header, "targets")
	return result
}

func (p *nodeChainCandidateMetadataPages) page(offset int, id string) string {
	if p == nil || offset < 0 {
		return ""
	}
	if p.legacy != "" {
		if offset != 0 {
			return ""
		}
		return p.legacy
	}
	end := len(p.targets)
	if id != "" {
		var found bool
		offset, found = p.index[id]
		if !found {
			return ""
		}
		end = offset + 1
	}
	if offset >= len(p.targets) {
		return ""
	}
	fields := make(map[string]json.RawMessage, len(p.header)+2)
	for key, value := range p.header {
		fields[key] = value
	}
	fields["target_offset"], _ = json.Marshal(offset)
	fields["targets"] = json.RawMessage("[]")
	header, _ := json.Marshal(fields)
	size := len(header)
	last := offset
	for last < end {
		cost := len(p.targets[last])
		if last > offset {
			cost++
		}
		if size+cost > nodeChainCandidatePageBytes {
			break
		}
		size += cost
		last++
	}
	if last == offset {
		return ""
	}
	fields["targets"], _ = json.Marshal(p.targets[offset:last])
	raw, _ := json.Marshal(fields)
	return string(raw)
}

// Every caller first validates its exact immutable source/operation. Only
// the canonical public header, ordered targets and digest are cached.
func (p *NodeChainCandidatePlan) wireMetadata(scope, capture string, build func() string, offset int32, id string) string {
	if capture == "" || p == nil || p.metadataPages == nil || offset < 0 {
		return ""
	}
	cache := p.metadataPages
	key := scope + ":" + capture
	cache.mu.Lock()
	if cache.values == nil {
		cache.values = make(map[string]*nodeChainCandidateMetadataPages)
	}
	pages := cache.values[key]
	cache.mu.Unlock()
	if pages == nil {
		compiled := compileNodeChainCandidateMetadataPages(build())
		if compiled == nil {
			return ""
		}
		cache.mu.Lock()
		pages = cache.values[key]
		if pages == nil {
			pages = compiled
			cache.values[key] = pages
		}
		cache.mu.Unlock()
	}
	return pages.page(int(offset), id)
}

func (p *NodeChainCandidatePlan) MetadataPage(offset int32) string {
	if p.validate() != nil {
		return ""
	}
	return p.wireMetadata("packet", p.capture, p.Metadata, offset, "")
}

func (p *NodeChainCandidatePreparation) MetadataPage(offset int32) string {
	if p == nil {
		return ""
	}
	return p.candidates.wireMetadata("preparation", p.CaptureSHA256(), p.Metadata, offset, "")
}

func (p *NodeChainSOCKSConnectedCandidatePlan) MetadataPage(offset int32) string {
	if p.validate() != nil {
		return ""
	}
	return p.plan.MetadataPage(offset)
}

func (p *NodeChainCONNECTConnectedCandidatePlan) MetadataPage(offset int32) string {
	if p.validate() != nil {
		return ""
	}
	return p.plan.MetadataPage(offset)
}

func (p *NodeChainExecutionCandidatePlan) MetadataPage(offset int32) string {
	if p == nil {
		return ""
	}
	return p.plan.wireMetadata("local", p.CaptureSHA256(), p.Metadata, offset, "")
}

func (p *NodeChainExecutionRemoteCandidatePlan) MetadataPage(offset int32) string {
	if p == nil || p.packet == nil || p.packet.validate() != nil {
		return ""
	}
	return p.packet.wireMetadata("remote", p.CaptureSHA256(), p.Metadata, offset, "")
}

func (p *NodeChainExecutionCandidatePlan) MetadataForCandidate(id string) string {
	if p == nil || id == "" {
		return ""
	}
	return p.plan.wireMetadata("local", p.CaptureSHA256(), p.Metadata, 0, id)
}

func (p *NodeChainExecutionRemoteCandidatePlan) MetadataForCandidate(id string) string {
	if p == nil || id == "" || p.packet == nil || p.packet.validate() != nil {
		return ""
	}
	return p.packet.wireMetadata("remote", p.CaptureSHA256(), p.Metadata, 0, id)
}
