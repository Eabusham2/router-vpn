package mobilemultihop

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDesktopStartupAdmissionKeepsOriginalDeadline(t *testing.T) {
	source, config, session := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 32)
	deadline := time.Now().Add(time.Minute)
	original, err := NewDesktopStartupAdmission("external", session, source, config, deadline)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := original.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"original", "duplicate", "unknown", "substituted-session", "substituted-source", "substituted-config", "wrong-kind", "expired", "shorter-caller"} {
		t.Run(mode, func(t *testing.T) {
			value := raw
			kind, ss, src, cfg := "external", session, source, config
			switch mode {
			case "duplicate":
				value = strings.Replace(value, `"schema":1,`, `"schema":1,"schema":1,`, 1)
			case "unknown":
				value = strings.TrimSuffix(value, "}") + `,"extra":1}`
			case "substituted-session":
				ss = strings.Repeat("d", 32)
			case "substituted-source":
				src = strings.Repeat("d", 64)
			case "substituted-config":
				cfg = strings.Repeat("d", 64)
			case "wrong-kind":
				kind = "tor"
			}
			parsed, err := ParseDesktopStartupAdmission(value, kind, ss, src, cfg)
			valid := mode == "original" || mode == "expired" || mode == "shorter-caller"
			if !valid {
				if err == nil {
					t.Fatal("foreign or noncanonical admission accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			parent := context.Background()
			expected := deadline
			if mode == "shorter-caller" {
				var cancel context.CancelFunc
				parent, cancel = context.WithTimeout(parent, time.Second)
				defer cancel()
				expected, _ = parent.Deadline()
			}
			if mode == "expired" {
				parsed.DeadlineNS = time.Now().Add(-time.Second).UnixNano()
			}
			ctx, cancel, err := parsed.Context(parent)
			if mode == "expired" {
				if !errors.Is(err, context.DeadlineExceeded) || ctx != nil || cancel != nil {
					t.Fatal("expired original budget renewed", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer cancel()
			actual, _ := ctx.Deadline()
			if !actual.Equal(expected) {
				t.Fatal("original absolute deadline changed")
			}
		})
	}
}
