package awgpolicy

import (
	"strings"
	"testing"
)

func parameters() map[string]string {
	return map[string]string{"jc": "3", "jmin": "40", "jmax": "900", "s1": "56", "s2": "48", "s3": "24", "s4": "32", "h1": "10-19", "h2": "20-29", "h3": "30-39", "h4": "40-49"}
}
func TestExactModeAndParameterContract(t *testing.T) {
	for _, m := range []string{"awg2-fast", "awg2-strong"} {
		if !IsMode(m) || !WireGuardFamily(m) {
			t.Fatal(m)
		}
	}
	if IsMode("wg") || !WireGuardFamily("wg") {
		t.Fatal("WG family classification")
	}
	for _, m := range []string{"awg", "awg2", "direct", "AWG2-fast", "awg2-fast\n"} {
		if IsMode(m) || WireGuardFamily(m) {
			t.Fatal(m)
		}
	}
	p := parameters()
	out, err := ParametersUAPI(p)
	if err != nil || len(strings.Split(strings.TrimSpace(out), "\n")) != 11 {
		t.Fatal(err, out)
	}
	for k, v := range p {
		if !strings.Contains(out, k+"="+v+"\n") {
			t.Fatal("parameter dropped", k)
		}
	}
	for _, fn := range []func(map[string]string){
		func(p map[string]string) { delete(p, "s4") }, func(p map[string]string) { p["listen_port"] = "42" },
		func(p map[string]string) { p["s4"] = "32\nprivate_key=unowned" }, func(p map[string]string) { p["jc"] = "129" },
		func(p map[string]string) { p["jmin"] = "901" }, func(p map[string]string) { p["h1"] = "4" }, func(p map[string]string) { p["h1"] = "19-10" },
		func(p map[string]string) { p["h2"] = "19-29" }, func(p map[string]string) { p["h4"] = "4294967296" },
		func(p map[string]string) { p["s2"] = "112" }, func(p map[string]string) { p["s3"] = "-1" },
	} {
		p := parameters()
		fn(p)
		if _, err := ParametersUAPI(p); err == nil {
			t.Fatal("invalid parameters accepted", p)
		}
	}
}
