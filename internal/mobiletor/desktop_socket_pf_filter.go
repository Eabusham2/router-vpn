package mobiletor

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// This is the finite filter grammar emitted by the owned Darwin guardian. It
// deliberately has no includes, macros, tables, routes, translation or global
// PF options. The native loader receives fully expanded, typed filter rules;
// the independent pfctl parser/readback remains a separate semantic check.
const desktopPFFilterLimit = 1024

type desktopPFFilterRule struct {
	Action          string
	Direction       string
	Quick           bool
	Interface       string
	Family          uint8
	Protocol        uint8
	Source          netip.Prefix
	Destination     netip.Prefix
	SourcePort      uint16
	DestinationPort uint16
	User            bool
	UID             uint32
	FlagsAny        bool
	Tag             string
	MatchTag        string
	MatchTagNot     bool
	KeepState       bool
	Floating        bool
	Label           string
	Anchor          string
}

type desktopPFWord struct {
	value  string
	quoted bool
}

type desktopPFRuleWords struct {
	words []desktopPFWord
	index int
}

var desktopPFFilterInterface = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)
var desktopPFFilterAnchor = regexp.MustCompile(`^/?[A-Za-z0-9_.:-]+(?:/[A-Za-z0-9_.:-]+)*$`)

func desktopPFFilterWords(line string) ([]desktopPFWord, error) {
	if len(line) > 4096 {
		return nil, errors.New("owned PF rule exceeds its input bound")
	}
	var words []desktopPFWord
	for at := 0; at < len(line); {
		if line[at] == ' ' || line[at] == '\t' {
			at++
			continue
		}
		start := at
		if line[at] == '"' {
			at++
			start = at
			for at < len(line) && line[at] != '"' {
				if line[at] < 32 || line[at] > 126 || line[at] == '\\' {
					return nil, errors.New("owned PF quoted field is not a literal ASCII value")
				}
				at++
			}
			if at == len(line) || at == start {
				return nil, errors.New("owned PF quoted field is empty or unterminated")
			}
			words = append(words, desktopPFWord{line[start:at], true})
			at++
			if at < len(line) && line[at] != ' ' && line[at] != '\t' {
				return nil, errors.New("owned PF quoted field has a concatenated suffix")
			}
			continue
		}
		if strings.ContainsRune("{},()!", rune(line[at])) {
			words = append(words, desktopPFWord{line[at : at+1], false})
			at++
			continue
		}
		for at < len(line) && line[at] != ' ' && line[at] != '\t' && !strings.ContainsRune("{},()!", rune(line[at])) {
			if line[at] < 33 || line[at] > 126 || strings.ContainsRune("\"'\\#$;=", rune(line[at])) {
				return nil, errors.New("owned PF field contains an unsupported control or expansion")
			}
			at++
		}
		words = append(words, desktopPFWord{line[start:at], false})
		if len(words) > 256 {
			return nil, errors.New("owned PF rule has too many fields")
		}
	}
	return words, nil
}

func (p *desktopPFRuleWords) take(value string) bool {
	if p.index < len(p.words) && !p.words[p.index].quoted && p.words[p.index].value == value {
		p.index++
		return true
	}
	return false
}

func (p *desktopPFRuleWords) field(quoted bool) (string, error) {
	if p.index >= len(p.words) || p.words[p.index].quoted != quoted {
		return "", errors.New("owned PF rule has a missing or incorrectly quoted field")
	}
	value := p.words[p.index].value
	p.index++
	return value, nil
}

func (p *desktopPFRuleWords) number(bits int, nonzero bool) (uint64, error) {
	value, err := p.field(false)
	if err != nil {
		return 0, err
	}
	number, err := strconv.ParseUint(value, 10, bits)
	if err != nil || strconv.FormatUint(number, 10) != value || nonzero && number == 0 {
		return 0, errors.New("owned PF numeric field is not a bounded canonical integer")
	}
	return number, nil
}

func (p *desktopPFRuleWords) name() (string, error) {
	value, err := p.field(true)
	if err != nil || len(value) > 63 {
		return "", errors.New("owned PF name exceeds its native field or lost its literal quoting")
	}
	return value, nil
}

func (p *desktopPFRuleWords) address() (netip.Prefix, error) {
	if p.take("any") {
		return netip.Prefix{}, nil
	}
	value, err := p.field(false)
	if err != nil {
		return netip.Prefix{}, err
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		address, addressErr := netip.ParseAddr(value)
		if addressErr != nil || address.Zone() != "" || address.Is4In6() {
			return netip.Prefix{}, errors.New("owned PF address is not a literal unscoped IP address")
		}
		prefix = netip.PrefixFrom(address, address.BitLen())
	}
	if prefix.Addr().Is4In6() || prefix != prefix.Masked() {
		return netip.Prefix{}, errors.New("owned PF prefix is mapped or contains nonzero host bits")
	}
	return prefix, nil
}

func (p *desktopPFRuleWords) addresses() ([]netip.Prefix, error) {
	if !p.take("{") {
		value, err := p.address()
		return []netip.Prefix{value}, err
	}
	var values []netip.Prefix
	for {
		value, err := p.address()
		if err != nil || len(values) >= 32 {
			return nil, errors.Join(err, errors.New("owned PF address list is invalid or exceeds its bound"))
		}
		values = append(values, value)
		if p.take("}") {
			return values, nil
		}
		if !p.take(",") {
			return nil, errors.New("owned PF address list has no explicit separator")
		}
	}
}

func desktopPFCompileFilterLine(words []desktopPFWord) ([]desktopPFFilterRule, error) {
	p := desktopPFRuleWords{words: words}
	var rule desktopPFFilterRule
	var err error
	if p.take("anchor") {
		rule.Action = "anchor"
		rule.Anchor, err = p.name()
		if err != nil || !desktopPFFilterAnchor.MatchString(rule.Anchor) {
			return nil, errors.New("owned PF dispatch has no bounded literal anchor")
		}
		for _, segment := range strings.Split(rule.Anchor, "/") {
			if segment == "." || segment == ".." {
				return nil, errors.New("owned PF dispatch cannot traverse its anchor namespace")
			}
		}
		if !p.take("out") {
			return nil, errors.New("owned PF dispatch must preserve the outbound direction")
		}
		rule.Direction = "out"
		p.take("all")
		if p.index != len(words) {
			return nil, errors.New("owned PF dispatch contains unsupported options")
		}
		return []desktopPFFilterRule{rule}, nil
	}
	if p.take("pass") {
		rule.Action = "pass"
	} else if p.take("block") && p.take("drop") {
		rule.Action = "block"
	} else {
		return nil, errors.New("owned PF loader accepts only pass, drop and anchor filters")
	}
	if p.take("out") {
		rule.Direction = "out"
	} else if p.take("in") {
		rule.Direction = "in"
	} else {
		return nil, errors.New("owned PF filter has no explicit direction")
	}
	rule.Quick = p.take("quick")
	if p.take("on") {
		rule.Interface, err = p.field(false)
		if err != nil || !desktopPFFilterInterface.MatchString(rule.Interface) {
			return nil, errors.New("owned PF filter has no bounded interface identity")
		}
	}
	if p.take("inet") {
		rule.Family = 4
	} else if p.take("inet6") {
		rule.Family = 6
	}
	if p.take("proto") {
		protocol, protocolErr := p.field(false)
		if protocolErr != nil {
			return nil, protocolErr
		}
		switch protocol {
		case "tcp":
			rule.Protocol = 6
		case "udp":
			rule.Protocol = 17
		case "icmp6":
			rule.Protocol = 58
			if rule.Family != 6 {
				return nil, errors.New("owned PF ICMPv6 filter has another address family")
			}
		default:
			return nil, errors.New("owned PF filter has an unsupported protocol")
		}
	}
	sources, destinations := []netip.Prefix{{}}, []netip.Prefix{{}}
	if !p.take("all") {
		from, to := p.take("from"), false
		if from {
			sources, err = p.addresses()
			if err != nil {
				return nil, err
			}
			if p.take("port") {
				port, portErr := p.number(16, true)
				if portErr != nil {
					return nil, portErr
				}
				rule.SourcePort = uint16(port)
			}
		}
		to = p.take("to")
		if to {
			destinations, err = p.addresses()
			if err != nil {
				return nil, err
			}
			if p.take("port") {
				port, portErr := p.number(16, true)
				if portErr != nil {
					return nil, portErr
				}
				rule.DestinationPort = uint16(port)
			}
		}
		if !from && !to {
			return nil, errors.New("owned PF filter has no explicit address scope")
		}
	}
	if p.take("user") {
		uid, uidErr := p.number(32, false)
		if uidErr != nil {
			return nil, uidErr
		}
		rule.User, rule.UID = true, uint32(uid)
	}
	if (rule.SourcePort != 0 || rule.DestinationPort != 0 || rule.User) && rule.Protocol != 6 && rule.Protocol != 17 {
		return nil, errors.New("owned PF port or UID requires an exact TCP/UDP transport")
	}
	if p.take("flags") {
		if !p.take("any") || rule.Protocol != 6 {
			return nil, errors.New("owned PF TCP flags changed the supported stateless contract")
		}
		rule.FlagsAny = true
	}
	if p.take("tag") {
		rule.Tag, err = p.name()
		if err != nil {
			return nil, err
		}
	}
	rule.MatchTagNot = p.take("!")
	if p.take("tagged") {
		rule.MatchTag, err = p.name()
		if err != nil {
			return nil, err
		}
	} else if rule.MatchTagNot {
		return nil, errors.New("owned PF tag negation lost its tagged selector")
	}
	if rule.Action == "pass" {
		if p.take("no") {
			if !p.take("state") {
				return nil, errors.New("owned PF pass lost its explicit stateless policy")
			}
		} else if p.take("keep") && p.take("state") {
			// Native negative fixtures deliberately create a scoped foreign
			// stateful rule. Production readback still rejects such a rule.
			rule.KeepState = true
			if p.take("(") {
				if !p.take("floating") || !p.take(")") {
					return nil, errors.New("owned PF state fixture changed its floating policy")
				}
				rule.Floating = true
			}
		} else {
			return nil, errors.New("owned PF pass requires an explicit state policy")
		}
	}
	if p.take("label") {
		rule.Label, err = p.name()
		if err != nil {
			return nil, err
		}
	}
	if p.index != len(words) {
		return nil, errors.New("owned PF filter contains unsupported or repeated options")
	}
	var result []desktopPFFilterRule
	for _, source := range sources {
		for _, destination := range destinations {
			expanded := rule
			expanded.Source, expanded.Destination = source, destination
			for _, endpoint := range []netip.Prefix{source, destination} {
				if !endpoint.IsValid() {
					continue
				}
				family := uint8(6)
				if endpoint.Addr().Is4() {
					family = 4
				}
				if expanded.Family != 0 && expanded.Family != family {
					return nil, errors.New("owned PF address expansion mixes incompatible families")
				}
				expanded.Family = family
			}
			result = append(result, expanded)
		}
	}
	return result, nil
}

func desktopPFCompileFilters(source string) ([]desktopPFFilterRule, error) {
	if len(source) > 512*1024 {
		return nil, errors.New("owned PF filter input exceeds its complete bound")
	}
	var rules []desktopPFFilterRule
	for index, line := range strings.Split(source, "\n") {
		words, err := desktopPFFilterWords(line)
		if err != nil {
			return nil, fmt.Errorf("owned PF filter line %d: %w", index+1, err)
		}
		if len(words) == 0 {
			continue
		}
		expanded, err := desktopPFCompileFilterLine(words)
		if err != nil || len(rules)+len(expanded) > desktopPFFilterLimit {
			return nil, errors.Join(err, fmt.Errorf("owned PF filter line %d is invalid or exceeds the native rule bound", index+1))
		}
		rules = append(rules, expanded...)
	}
	return rules, nil
}
