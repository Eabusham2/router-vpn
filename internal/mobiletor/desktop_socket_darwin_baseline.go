//go:build darwin

package mobiletor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

func desktopDarwinPFNamespacePresent(ctx context.Context, anchor string) (bool, error) {
	if !desktopPFInventoryPath(anchor) {
		return false, errors.New("Darwin PF presence read has no bounded namespace")
	}
	parent := ""
	for _, name := range strings.Split(anchor, "/") {
		arguments := []string{"-s", "Anchors"}
		if parent != "" {
			arguments = append([]string{"-a", parent}, arguments...)
		}
		raw, err := desktopDarwinCommand(ctx, "/sbin/pfctl", nil, arguments...)
		if err != nil {
			return false, err
		}
		children, err := desktopPFInventoryChildren(parent, raw)
		if err != nil {
			return false, err
		}
		next := name
		if parent != "" {
			next = parent + "/" + name
		}
		found := false
		for _, child := range children {
			found = found || child == next
		}
		if !found {
			return false, nil
		}
		parent = next
	}
	return true, nil
}

func desktopDarwinPFBaselineRead(ctx context.Context) (DesktopDarwinPFBaselineProof, string, error) {
	var proof DesktopDarwinPFBaselineProof
	present, err := desktopDarwinPFNamespacePresent(ctx, desktopDarwinPFNamespace)
	if err != nil || !present {
		return proof, "", err
	}
	rules, err := desktopDarwinPFRead(ctx, desktopDarwinPFNamespace)
	if err != nil {
		return proof, "", err
	}
	present, err = desktopDarwinPFNamespacePresent(ctx, desktopDarwinPFNamespace)
	if err != nil || !present {
		return proof, "", errors.Join(err, errors.New("Darwin PF baseline namespace changed during its rule readback"))
	}
	return DesktopDarwinPFBaselineProof{Present: true, RulesSHA256: desktopPFDigest([]byte(rules))}, rules, nil
}

var desktopDarwinBaselineSlot = regexp.MustCompile(`^anchor "(p[0-9a-f]{32})" out(?: all)?$`)

func desktopDarwinPFBaselineReady(ctx context.Context, rules string, present bool) error {
	if !present {
		return nil
	}
	// The current baseline itself may retain one empty dispatch slot. That
	// slot is named in the independently matched baseline. A live generation,
	// an unreferenced sibling or any child-owned rules/tables require the exact
	// guardian to finish; this utility cannot recursively adopt or erase them.
	allowed := make(map[string]bool)
	for _, line := range strings.Split(rules, "\n") {
		if !strings.HasPrefix(line, "anchor ") {
			continue
		}
		match := desktopDarwinBaselineSlot.FindStringSubmatch(line)
		if len(match) != 2 || len(allowed) != 0 {
			return errors.New("Darwin PF baseline contains another dispatch owner")
		}
		allowed[desktopDarwinPFNamespace+"/"+match[1]] = true
	}
	if err := desktopDarwinPFNoTranslation(ctx, desktopDarwinPFNamespace); err != nil {
		return err
	}
	tables, err := desktopDarwinCommand(ctx, "/sbin/pfctl", nil, "-a", desktopDarwinPFNamespace, "-s", "Tables")
	if err != nil || strings.TrimSpace(string(tables)) != "" {
		return errors.Join(err, errors.New("Darwin PF baseline retains an unowned table"))
	}
	raw, err := desktopDarwinCommand(ctx, "/sbin/pfctl", nil, "-a", desktopDarwinPFNamespace, "-s", "Anchors")
	if err != nil {
		return err
	}
	children, err := desktopPFInventoryChildren(desktopDarwinPFNamespace, raw)
	if err != nil {
		return err
	}
	for _, child := range children {
		if !allowed[child] {
			return errors.New("Darwin PF baseline has an unjoined or unreferenced child owner")
		}
		filters, err := desktopDarwinPFRead(ctx, child)
		if err != nil || filters != "" {
			return errors.Join(err, errors.New("Darwin PF baseline child still has captured runtime rules"))
		}
		if err := desktopDarwinPFNoTranslation(ctx, child); err != nil {
			return err
		}
		for _, kind := range []string{"Tables", "Anchors"} {
			owned, err := desktopDarwinCommand(ctx, "/sbin/pfctl", nil, "-a", child, "-s", kind)
			if err != nil || strings.TrimSpace(string(owned)) != "" {
				return errors.Join(err, fmt.Errorf("Darwin PF baseline child retains its own %s", kind))
			}
		}
	}
	return nil
}

// RunDesktopDarwinPFBaseline handles only the compiled fixed baseline. The
// installed controller utility owns its installation/state lock across this
// call. No caller can select a PF namespace, filter text or executable path.
func RunDesktopDarwinPFBaseline(ctx context.Context, raw []byte, apply bool) ([]byte, error) {
	if ctx == nil || os.Getuid() != 0 || os.Geteuid() != 0 {
		return nil, errors.New("Darwin PF baseline requires its retained privileged utility")
	}
	if len(raw) > DesktopDarwinPFBaselineLimit {
		return nil, errors.New("Darwin PF baseline request exceeds its bound")
	}
	raw = append([]byte(nil), raw...)
	request, err := ParseDesktopDarwinPFBaselineRequest(raw)
	if err != nil {
		return nil, err
	}
	if _, err := desktopDarwinPFCapturedABI(); err != nil {
		return nil, err
	}
	var target DesktopDarwinPFBaselineProof
	var compiled []desktopPFFilterRule
	if request.Action == "replace" {
		source := desktopPFOwnedBaseline(request.SessionID, request.SourceSHA256, request.HomeLANAccess, desktopDarwinPFTestScope)
		compiled, err = desktopPFCompileFilters(source)
		if err != nil || len(compiled) == 0 {
			return nil, errors.Join(err, errors.New("Darwin PF baseline lost its finite compiled filter policy"))
		}
		canonical, err := desktopDarwinPFCanonical(ctx, source)
		if err != nil || canonical == "" {
			return nil, errors.Join(err, errors.New("Darwin PF baseline did not independently parse"))
		}
		target = DesktopDarwinPFBaselineProof{Present: true, RulesSHA256: desktopPFDigest([]byte(canonical))}
	}
	var current DesktopDarwinPFBaselineProof
	var currentRules string
	backend := desktopPFBaselineBackend{
		read: func(ctx context.Context) (DesktopDarwinPFBaselineProof, error) {
			var err error
			current, currentRules, err = desktopDarwinPFBaselineRead(ctx)
			return current, err
		},
		ready: func(ctx context.Context) error {
			return desktopDarwinPFBaselineReady(ctx, currentRules, current.Present)
		},
		replace: func(ctx context.Context) error {
			return desktopDarwinPFNativeReplace(ctx, desktopDarwinPFNamespace, compiled)
		},
	}
	result, err := desktopPFTransitionBaseline(ctx, request, target, apply, backend)
	if err != nil {
		return nil, err
	}
	return json.Marshal(result)
}
