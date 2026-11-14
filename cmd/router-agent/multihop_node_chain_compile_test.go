package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"router-vpn/internal/mobilemultihop"
)

func TestOrderedPrivateCompilersRejectUnboundedAmbiguousAndSecretInput(t *testing.T) {
	for name, compile := range map[string]func(io.Reader, io.Writer) error{
		"plan": compileServerNodeChainPlan, "source": compileServerNodeChainSource,
	} {
		t.Run(name, func(t *testing.T) {
			inputs := []struct {
				name string
				read io.Reader
			}{
				{"empty", strings.NewReader("")},
				{"null", strings.NewReader("null")},
				{"array", strings.NewReader("[]")},
				{"duplicate", strings.NewReader(`{"schema":1,"schema":1,"private":"must-not-echo-private-value"}`)},
				{"trailing", strings.NewReader(`{} {"private":"must-not-echo-private-value"}`)},
				{"unknown", strings.NewReader(`{"schema":1,"private":"must-not-echo-private-value"}`)},
				{"reader", iotest.ErrReader(errors.New("must-not-echo-private-value"))},
				{"oversized", io.LimitReader(zeroOrderedPairingReader{}, mobilemultihop.NodeChainInputLimit+4097)},
			}
			for _, input := range inputs {
				t.Run(input.name, func(t *testing.T) {
					var output bytes.Buffer
					err := compile(input.read, &output)
					if err == nil || output.Len() != 0 || strings.Contains(err.Error(), "must-not-echo-private-value") {
						t.Fatal("private compiler emitted partial source or echoed rejected input")
					}
				})
			}
		})
	}
}

type zeroOrderedPairingReader struct{}

func (zeroOrderedPairingReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}
