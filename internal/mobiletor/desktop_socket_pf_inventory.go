package mobiletor

import (
	"errors"
	"regexp"
	"strings"
)

var desktopPFInventoryName = regexp.MustCompile(`^[A-Za-z0-9_.:-]+$`)

func desktopPFInventoryPath(path string) bool {
	if path == "" || len(path) > 1023 {
		return false
	}
	for _, name := range strings.Split(path, "/") {
		if name == "." || name == ".." || !desktopPFInventoryName.MatchString(name) {
			return false
		}
	}
	return true
}

// Native pfctl lists directly owned child anchors even when no filter rule
// dispatches to them. A wildcard rules read follows dispatch and can therefore
// miss an orphaned prior owner. Resolve only exact immediate child names and
// read each directly; no inventory result authorizes a load, flush or deletion.
func desktopPFInventoryChildren(parent string, raw []byte) ([]string, error) {
	if parent != "" && !desktopPFInventoryPath(parent) || len(raw) > 64<<10 {
		return nil, errors.New("Darwin PF child inventory exceeds its captured path or output bound")
	}
	var result []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		name := strings.TrimSpace(line)
		if name == "" {
			continue
		}
		path := name
		if parent != "" {
			name = strings.TrimPrefix(name, parent+"/")
			path = parent + "/" + name
		}
		if !desktopPFInventoryName.MatchString(name) || name == "." || name == ".." ||
			!desktopPFInventoryPath(path) || seen[path] || len(result) >= 256 {
			return nil, errors.New("Darwin PF child inventory has an ambiguous or escaping anchor identity")
		}
		seen[path] = true
		result = append(result, path)
	}
	return result, nil
}

func desktopPFRejectLegacyRules(root string, readRules func(string) (string, error), readChildren func(string) ([]byte, error)) error {
	if !desktopPFInventoryPath(root) || readRules == nil || readChildren == nil {
		return errors.New("Darwin PF legacy inventory has no captured reader")
	}
	// A missing ruleset is not a failed read to ignore: Darwin returns EINVAL
	// when enumerating it. Prove absence from its existing parent, starting
	// at the always-present global tree, before querying the legacy root.
	parent := ""
	for _, name := range strings.Split(root, "/") {
		raw, err := readChildren(parent)
		if err != nil {
			return err
		}
		children, err := desktopPFInventoryChildren(parent, raw)
		if err != nil {
			return err
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
			return nil
		}
		parent = next
	}
	queue := []string{root}
	for index := 0; index < len(queue); index++ {
		anchor := queue[index]
		rules, err := readRules(anchor)
		if err != nil {
			return err
		}
		if strings.TrimSpace(rules) != "" {
			return errors.New("Darwin PF retains an earlier nested physical owner; exact prior-owner recovery is required")
		}
		raw, err := readChildren(anchor)
		if err != nil {
			return err
		}
		children, err := desktopPFInventoryChildren(anchor, raw)
		if err != nil {
			return err
		}
		if len(queue)+len(children) > 256 || len(children) != 0 && strings.Count(anchor, "/")-strings.Count(root, "/") >= 8 {
			return errors.New("Darwin PF legacy inventory exceeds its bounded tree")
		}
		queue = append(queue, children...)
	}
	return nil
}
