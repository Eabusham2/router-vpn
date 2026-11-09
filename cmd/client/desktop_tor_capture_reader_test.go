package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
)

type desktopTorCaptureReadFunc func([]byte) (int, error)

func (read desktopTorCaptureReadFunc) Read(p []byte) (int, error) { return read(p) }

func TestDesktopTorCaptureReaderPreservesEOFAndReadErrors(t *testing.T) {
	const payload = "the complete captured executable bytes"
	for _, scenario := range []string{"separate-eof", "data-eof", "partial-read-error"} {
		t.Run(scenario, func(t *testing.T) {
			var source io.Reader = strings.NewReader(payload)
			var expected error
			if scenario != "separate-eof" {
				ending := io.EOF
				if scenario == "partial-read-error" {
					expected = errors.New("captured executable read failed")
					ending = expected
				}
				source = desktopTorCaptureReadFunc(func(p []byte) (int, error) { return copy(p, payload), ending })
			}
			digest := sha256.New()
			count, err := io.Copy(digest, io.LimitReader(desktopTorCaptureReader{ctx: context.Background(), reader: source}, int64(len(payload)+1)))
			if err != expected || count != int64(len(payload)) || hex.EncodeToString(digest.Sum(nil)) != desktopTorDigest([]byte(payload)) {
				t.Fatal("joined capture wrapped healthy EOF or lost the actual read failure", count, err, expected)
			}
		})
	}
}

func TestDesktopTorCaptureReaderRejectsCancellationAtReadCompletion(t *testing.T) {
	for _, scenario := range []string{"before-read", "during-data", "at-empty-eof", "at-data-eof", "with-read-error"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "before-read" {
				cancel()
			}
			failure := errors.New("original file read failure")
			calls := 0
			source := desktopTorCaptureReadFunc(func(p []byte) (int, error) {
				calls++
				cancel() // Causal cancellation while the actual Read is entered.
				if scenario == "at-empty-eof" {
					return 0, io.EOF
				}
				n := copy(p, "captured bytes")
				if scenario == "at-data-eof" {
					return n, io.EOF
				}
				if scenario == "with-read-error" {
					return n, failure
				}
				return n, nil
			})
			_, err := io.Copy(sha256.New(), desktopTorCaptureReader{ctx: ctx, reader: source})
			if !errors.Is(err, context.Canceled) || scenario == "with-read-error" && !errors.Is(err, failure) {
				t.Fatal("file completion swallowed the original cancellation or read error", err)
			}
			if scenario == "before-read" && calls != 0 || scenario != "before-read" && calls != 1 {
				t.Fatal("cancelled hash entered or continued another file read", calls)
			}
		})
	}
}
