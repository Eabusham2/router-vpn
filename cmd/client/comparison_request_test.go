package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestComparisonRequestNonceRejectsAmbiguousJSONWithoutDowngradingSourceChecks(t *testing.T) {
	good := strings.Repeat("a1", 16)
	for _, kind := range []string{"external", "speed-lab"} {
		t.Run(kind, func(t *testing.T) {
			decode := func(raw string) (string, error) {
				if kind == "external" {
					q, err := decodeExternalProfileConnectRequest(strings.NewReader(raw))
					return q.ComparisonRequestID, err
				}
				var q speedLabRequest
				err := json.Unmarshal([]byte(raw), &q)
				return q.ComparisonRequestID, err
			}
			if got, err := decode(`{"comparison_request_id":"` + good + `"}`); err != nil || got != good {
				t.Fatal("exact request identity did not survive decoding", err)
			}
			if got, err := decode(`{}`); err != nil || got != "" {
				t.Fatal("omitted correlation changed legacy request decoding", err)
			}
			for _, raw := range []string{
				`{"comparison_request_id":null}`, `{"comparison_request_id":true}`, `{"comparison_request_id":32}`,
				`{"comparison_request_id":""}`, `{"comparison_request_id":"` + strings.ToUpper(good) + `"}`,
				`{"comparison_request_id":"` + good[:31] + `"}`, `{"comparison_request_id":"` + good + `0"}`,
				`{"comparison_request_id":"` + strings.Repeat("z", 32) + `"}`,
				`{"Comparison_Request_ID":"` + good + `"}`,
				`{"comparison_request_id":"` + good + `","comparison_request_id":"` + good + `"}`,
				`{"comparison_request_id":"` + good + `","Comparison_Request_ID":"` + good + `"}`,
				`{"comparison_request_id":"` + good + `","unrecognized":true}`,
				`{"comparison_request_id":"` + good + `"} {}`,
			} {
				if _, err := decode(raw); err == nil {
					t.Fatal("malformed or ambiguous progress identity was accepted", raw)
				}
			}
			if kind == "external" {
				for _, raw := range []string{
					`{"comparison_request_id":"` + good + `","expected_selected_node_id":"selected"}`,
					`{"comparison_request_id":"` + good + `","expected_selected_node_id":null,"expected_profile_tokens":{}}`,
				} {
					if _, err := decode(raw); err == nil {
						t.Fatal("request correlation bypassed private-source expectation validation")
					}
				}
			}
		})
	}
}
