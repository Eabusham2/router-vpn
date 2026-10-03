// Package awgpolicy validates the unchanged upstream AmneziaWG obfuscation
// parameters shared by mobile endpoints and private server-side relay leases.
package awgpolicy

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const Type = "routervpn-amneziawg"

func IsMode(mode string) bool          { return mode == "awg2-fast" || mode == "awg2-strong" }
func WireGuardFamily(mode string) bool { return mode == "wg" || IsMode(mode) }
func boundedNumber(text string, low, high int) (int, error) {
	if text == "" || strings.Trim(text, "0123456789") != "" {
		return 0, errors.New("invalid bounded integer")
	}
	n, err := strconv.Atoi(text)
	if err != nil || n < low || n > high {
		return 0, errors.New("integer outside native bound")
	}
	return n, nil
}

func IsParameter(key string) bool {
	switch key {
	case "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4":
		return true
	}
	return false
}
func ParametersUAPI(parameters map[string]string) (string, error) {
	if len(parameters) != 11 {
		return "", errors.New("native AmneziaWG requires its complete generated obfuscation policy")
	}
	for key := range parameters {
		if !IsParameter(key) {
			return "", errors.New("unowned AmneziaWG parameter")
		}
	}
	values := map[string]int{}
	for _, key := range []string{"jc", "jmin", "jmax", "s1", "s2", "s3", "s4"} {
		max := 1280
		if key == "jc" {
			max = 128
		}
		n, err := boundedNumber(parameters[key], 0, max)
		if err != nil {
			return "", errors.New("AmneziaWG noise or padding exceeds its bounded native budget")
		}
		values[key] = n
	}
	if values["jmin"] > values["jmax"] || values["s1"]+148 == values["s2"]+92 {
		return "", errors.New("inconsistent AmneziaWG padding sizes")
	}
	ranges := [][2]uint64{}
	for _, key := range []string{"h1", "h2", "h3", "h4"} {
		parts := strings.Split(parameters[key], "-")
		if len(parts) < 1 || len(parts) > 2 {
			return "", errors.New("invalid AmneziaWG header range")
		}
		bounds := [2]uint64{}
		for i, text := range parts {
			if text == "" || strings.Trim(text, "0123456789") != "" {
				return "", errors.New("invalid AmneziaWG header range")
			}
			n, err := strconv.ParseUint(text, 10, 32)
			if err != nil || n <= 4 {
				return "", errors.New("AmneziaWG headers must not masquerade as ordinary WireGuard")
			}
			bounds[i] = n
		}
		if len(parts) == 1 {
			bounds[1] = bounds[0]
		}
		if bounds[1] < bounds[0] {
			return "", errors.New("reversed AmneziaWG header range")
		}
		for _, other := range ranges {
			if bounds[0] <= other[1] && other[0] <= bounds[1] {
				return "", errors.New("AmneziaWG header ranges overlap")
			}
		}
		ranges = append(ranges, bounds)
	}
	keys := make([]string, 0, len(parameters))
	for key := range parameters {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var out bytes.Buffer
	for _, key := range keys {
		fmt.Fprintf(&out, "%s=%s\n", key, parameters[key])
	}
	return out.String(), nil
}
