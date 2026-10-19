package meeklite

import (
	"testing"

	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
)

func TestClientTargets(t *testing.T) {
	args := pt.Args{
		"targets": []string{"https://example.com/test|frontexample.com,https://example2.com/foo|example2front.info+anotherfront.net"},
	}

	ca, err := newClientArgs(&args)
	if err != nil {
		t.Fatal("Error parsing args", err)
	}
	if len(ca.fronts.list) != 3 {
		t.Error("There should be 3 fronts", ca.fronts)
	}

	for _, front := range ca.fronts.list {
		switch front.front {
		case "frontexample.com":
			if front.url.String() != "https://example.com/test" {
				t.Error("Wrong front pair", front.front, front.url)
			}
		case "example2front.info":
			if front.url.String() != "https://example2.com/foo" {
				t.Error("Wrong front pair", front.front, front.url)
			}
		case "anotherfront.net":
			if front.url.String() != "https://example2.com/foo" {
				t.Error("Wrong front pair", front.front, front.url)
			}
		default:
			t.Error("Wrong front pair", front.front, front.url)
		}
	}
}

func TestParseTargets(t *testing.T) {
	testTargets := map[string][2]string{
		"https://example.com/test|":                  [2]string{"https://example.com/test", ""},
		"https://example.com/+test|frontexample.com": [2]string{"https://example.com/+test", "frontexample.com"},
		"https://example.com/,test|frontexample.com": [2]string{"https://example.com/,test", "frontexample.com"},
	}
	for targets, frontPair := range testTargets {
		fl, err := parseTargets(targets)
		if err != nil {
			t.Error("Error parsing targets", targets, ":", err)
			continue
		}

		if fl.URL().String() != frontPair[0] {
			t.Error("Wrong url, got", fl.URL().String(), "expected", frontPair[0])
		}
		if fl.Front() != frontPair[1] {
			t.Error("Wrong front, got", fl.Front(), "expected", frontPair[1])
		}
	}
}

func TestParseTargetsFailures(t *testing.T) {
	testTargets := []string{
		"|frontexample.com",
		"ftp://example.com|",
	}
	for _, targets := range testTargets {
		_, err := parseTargets(targets)
		if err == nil {
			t.Error("targets", targets, "should have given an error")
		}
	}

}
