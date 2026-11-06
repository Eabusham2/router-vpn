//go:build linux

package systembootstrap

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"

	"router-vpn/internal/common"
)

// ResolvedAlias is the first exact-name link in a complete DNS response.
// Decoding proves framing and name relationships only. The caller separately
// retains the local validator verdict, loaded trust plan and selected scope.
type ResolvedAlias struct {
	Name, Target, Owner, DomainTarget string
	TTL                               uint32
	DNAME                             bool
}

func ResolvedAliasStep(question, response []byte) (*ResolvedAlias, error) {
	if err := common.ValidateDNSProbeResponse(question, response); err != nil {
		return nil, err
	}
	name, _, err := dnsName(question, 12)
	if err != nil || !validName(name) {
		return nil, errors.New("alias proof omitted original hostname")
	}
	_, offset, err := dnsName(response, 12)
	if err != nil {
		return nil, err
	}
	offset += 4
	var cname, dname *ResolvedAlias
	address := false
	for count := int(binary.BigEndian.Uint16(response[6:8])); count > 0; count-- {
		owner, end, err := dnsName(response, offset)
		if err != nil {
			return nil, err
		}
		kind, class := binary.BigEndian.Uint16(response[end:]), binary.BigEndian.Uint16(response[end+2:])
		ttl, size := binary.BigEndian.Uint32(response[end+4:]), int(binary.BigEndian.Uint16(response[end+8:]))
		offset = end + 10 + size
		if class != 1 {
			continue
		}
		if owner == name && (kind == 1 || kind == 28) {
			address = true
		}
		if kind != 5 && kind != 39 {
			continue
		}
		target, next, err := dnsName(response, end+10)
		if err != nil || next != offset || !validName(target) {
			return nil, errors.New("alias record has malformed target")
		}
		if kind == 5 && owner == name {
			if cname != nil && cname.Target != target {
				return nil, errors.New("original CNAME has conflicting targets")
			}
			if cname == nil || ttl < cname.TTL {
				cname = &ResolvedAlias{Name: name, Target: target, Owner: owner, TTL: ttl}
			}
		}
		if kind == 39 && strings.HasSuffix(name, "."+owner) {
			derived := strings.TrimSuffix(name, owner) + target
			if !validName(derived) {
				return nil, errors.New("DNAME substitution exceeds original hostname bound")
			}
			if dname != nil && dname.Owner == owner && dname.DomainTarget != target {
				return nil, errors.New("original DNAME has conflicting targets")
			}
			if dname == nil || len(owner) > len(dname.Owner) || owner == dname.Owner && ttl < dname.TTL {
				dname = &ResolvedAlias{Name: name, Target: derived, Owner: owner, DomainTarget: target, TTL: ttl, DNAME: true}
			}
		}
	}
	step := cname
	if dname != nil {
		if cname != nil && cname.Target != dname.Target {
			return nil, errors.New("synthesized CNAME differs from original DNAME")
		}
		if cname != nil && cname.TTL < dname.TTL {
			dname.TTL = cname.TTL
		}
		step = dname
	}
	if step != nil && (step.Target == name || address) {
		return nil, errors.New("original alias is cyclic or coexists with an address")
	}
	return step, nil
}

// ResolvedAliasQuery retains the original address-query options while giving
// each new name its own transaction. Type5 is reserved for an explicit local
// alias proof; QuestionMatchesName and ordinary physical admission stay A/AAAA.
func ResolvedAliasQuery(original []byte, name string, kind uint16) ([]byte, error) {
	if len(original) < 12 || kind != 1 && kind != 28 && kind != 5 {
		return nil, errors.New("alias query changed captured question purpose")
	}
	first, _, err := dnsName(original, 12)
	if err != nil || !QuestionMatchesName(original, first) {
		return nil, errors.New("alias query omitted original generated address question")
	}
	base := kind
	if base == 5 {
		base = 1
	}
	q, err := queryFor(name, base, original[3]&0x20 != 0, original[11] == 1)
	if err != nil {
		return nil, err
	}
	if kind == 5 {
		_, end, e := dnsName(q, 12)
		if e != nil {
			return nil, e
		}
		binary.BigEndian.PutUint16(q[end:], 5)
	}
	return q, nil
}

func resolvedAliasNameWire(name string) []byte {
	var out []byte
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0)
}
func resolvedAliasRecord(out []byte, owner string, kind uint16, ttl uint32, data []byte) []byte {
	out = append(out, resolvedAliasNameWire(owner)...)
	header := make([]byte, 10)
	binary.BigEndian.PutUint16(header, kind)
	binary.BigEndian.PutUint16(header[2:], 1)
	binary.BigEndian.PutUint32(header[4:], ttl)
	binary.BigEndian.PutUint16(header[8:], uint16(len(data)))
	out = append(out, header...)
	return append(out, data...)
}

// ResolvedLocalAddressAnswer carries an authenticated original-daemon local
// result to the address parser. Local policy is rechecked separately; this
// synthetic result has no DNSSEC AD claim or cache lifetime.
func ResolvedLocalAddressAnswer(question []byte, addresses []netip.Addr) ([]byte, error) {
	name, end, err := dnsName(question, 12)
	if err != nil || !QuestionMatchesName(question, name) || len(addresses) > 32 {
		return nil, errors.New("local alias target omitted its bounded original question")
	}
	kind := binary.BigEndian.Uint16(question[end:])
	answer := append([]byte(nil), question[:end+4]...)
	answer[2], answer[3] = 0x81, 0x80
	for i := 6; i < 12; i++ {
		answer[i] = 0
	}
	seen := map[netip.Addr]bool{}
	count := 0
	for _, address := range addresses {
		if !address.IsGlobalUnicast() || address.IsLoopback() || address.Is4In6() || address.Zone() != "" {
			return nil, errors.New("local alias target has unusable address")
		}
		if kind == 1 && !address.Is4() || kind == 28 && !address.Is6() || seen[address] {
			continue
		}
		seen[address] = true
		answer = resolvedAliasRecord(answer, name, kind, 0, address.AsSlice())
		count++
	}
	binary.BigEndian.PutUint16(answer[6:], uint16(count))
	return answer, common.ValidateDNSProbeResponse(question, answer)
}

// ResolvedAliasAnswer composes only proved links and the final exact-name
// address records. It never copies compressed records to a different offset,
// flattens an alias into an invented address owner, or infers security from AD.
func ResolvedAliasAnswer(original []byte, steps []ResolvedAlias, finalQuestion, finalResponse []byte, secure bool) ([]byte, error) {
	if len(steps) == 0 || len(steps) >= 16 {
		return nil, errors.New("alias chain omitted links or exceeded original bound")
	}
	if err := common.ValidateDNSProbeResponse(finalQuestion, finalResponse); err != nil {
		return nil, err
	}
	name, end, err := dnsName(original, 12)
	if err != nil || !QuestionMatchesName(original, name) {
		return nil, errors.New("alias result lost original address question")
	}
	kind := binary.BigEndian.Uint16(original[end:])
	finalName, finalEnd, err := dnsName(finalQuestion, 12)
	if err != nil || finalEnd+4 > len(finalQuestion) || binary.BigEndian.Uint16(finalQuestion[finalEnd:]) != kind {
		return nil, errors.New("alias target changed original address family")
	}
	if alias, err := ResolvedAliasStep(finalQuestion, finalResponse); err != nil || alias != nil {
		return nil, errors.Join(err, errors.New("alias result retained an unresolved final link"))
	}
	answer := append([]byte(nil), original[:end+4]...)
	answer[2] = (answer[2] & 1) | 0x80
	answer[3] = (original[3] & 0x10) | 0x80 | (finalResponse[3] & 15)
	if secure {
		answer[3] |= 0x20
	}
	for i := 6; i < 12; i++ {
		answer[i] = 0
	}
	count := 0
	seen := map[string]bool{}
	for _, step := range steps {
		if !validName(step.Name) || !validName(step.Target) || step.Name != name || seen[name] || step.Target == name {
			return nil, errors.New("alias chain changed, repeated or escaped its original name")
		}
		seen[name] = true
		if step.DNAME {
			if !validName(step.Owner) || !validName(step.DomainTarget) || !strings.HasSuffix(name, "."+step.Owner) || strings.TrimSuffix(name, step.Owner)+step.DomainTarget != step.Target {
				return nil, errors.New("alias chain changed original DNAME substitution")
			}
			answer = resolvedAliasRecord(answer, step.Owner, 39, step.TTL, resolvedAliasNameWire(step.DomainTarget))
			count++
		} else if step.Owner != step.Name || step.DomainTarget != "" {
			return nil, errors.New("alias chain changed original CNAME owner")
		}
		answer = resolvedAliasRecord(answer, step.Name, 5, step.TTL, resolvedAliasNameWire(step.Target))
		count++
		name = step.Target
	}
	if name != finalName || seen[name] {
		return nil, errors.New("alias result belongs to another target or a cycle")
	}
	_, offset, err := dnsName(finalResponse, 12)
	if err != nil {
		return nil, err
	}
	offset += 4
	addresses := 0
	for n := int(binary.BigEndian.Uint16(finalResponse[6:8])); n > 0; n-- {
		owner, end, err := dnsName(finalResponse, offset)
		if err != nil {
			return nil, err
		}
		rtype, class := binary.BigEndian.Uint16(finalResponse[end:]), binary.BigEndian.Uint16(finalResponse[end+2:])
		ttl, size := binary.BigEndian.Uint32(finalResponse[end+4:]), int(binary.BigEndian.Uint16(finalResponse[end+8:]))
		offset = end + 10 + size
		if owner != finalName || rtype != kind || class != 1 {
			continue
		}
		data := finalResponse[end+10 : offset]
		ip, ok := netip.AddrFromSlice(data)
		if !ok || kind == 1 && size != 4 || kind == 28 && size != 16 || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.Is4In6() {
			return nil, errors.New("alias target supplied an unusable address")
		}
		if finalResponse[3]&15 != 0 {
			return nil, errors.New("negative alias target also supplied addresses")
		}
		addresses++
		if addresses > 32 {
			return nil, errors.New("alias target exceeded original address bound")
		}
		answer = resolvedAliasRecord(answer, finalName, kind, ttl, data)
		count++
	}
	if len(answer) > 65535 {
		return nil, errors.New("composed alias answer exceeds DNS wire bound")
	}
	binary.BigEndian.PutUint16(answer[6:], uint16(count))
	if _, err := addressesFor(original, answer); err != nil {
		return nil, err
	}
	return answer, nil
}
