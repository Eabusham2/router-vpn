package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"time"
	"unicode/utf8"

	"router-vpn/internal/hopmeasure"
)

const desktopOrderedHistoryLimit = 1 << 20
const desktopOrderedHistoryEntries = 128

var desktopOrderedSessionID = regexp.MustCompile(`^session-[0-9]{1,20}-[0-9]{1,20}$`)
var desktopOrderedDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)

type desktopOrderedLatencyHistory struct {
	Schema   int                                `json:"schema"`
	Receipts []hopmeasure.OrderedLatencyReceipt `json:"receipts"`
}

func desktopOrderedReceiptKey(r hopmeasure.OrderedLatencyReceipt) string {
	return fmt.Sprintf("%s:%s:%d:%s:%s:%s", r.SourceSHA256, r.ConfigSHA256, r.Position, r.NodeID, r.Result.Kind, r.Result.Benchmark.Measurement)
}

// A historical receipt never grants current readiness or direct-node ranking.
// Fixed labels/metrics also prevent an endpoint, credential or arbitrary child
// string from being laundered into the private history or native UI.
func validateDesktopOrderedReceipt(r hopmeasure.OrderedLatencyReceipt, now time.Time) error {
	bad := errors.New("ordered history requires an exact complete fifty-response receipt")
	if r.Schema != 1 || !desktopOrderedDigest.MatchString(r.SourceSHA256) || !desktopOrderedDigest.MatchString(r.ConfigSHA256) || !desktopOrderedDigest.MatchString(r.GenerationSHA256) || !desktopMTURequestPattern.MatchString(r.Request) || r.Position < 0 || r.Position > 2 || !validProfileID(r.NodeID) || r.MeasuredAt <= 0 || r.MeasuredAt > now.Add(time.Second).UnixMilli() {
		return bad
	}
	result := r.Result
	role, kind, label, metric, endpoint := desktopOrderedLatencyMeaning(r.Position)
	if result.ID != r.NodeID || result.Role != role || result.Kind != kind || result.Label != label || !result.Ready || result.Failure != "" || result.Idle != nil || result.Download != nil || result.Upload != nil || result.Response != nil || result.Benchmark == nil {
		return bad
	}
	b := result.Benchmark
	if b.Schema != 1 || b.Measurement != metric || b.Endpoint != endpoint || b.Attempts != 50 || b.Failed != 0 || b.Distribution == nil || b.Distribution.Samples != 50 {
		return bad
	}
	d := b.Distribution
	maximum := float64(2000)
	if r.Position == 1 {
		maximum = 5000
	} // Original private/public probe budgets, in milliseconds.
	if d.Max > maximum || d.Jitter > d.Max-d.Min+1e-9 {
		return bad
	}
	for _, v := range []float64{d.Min, d.Median, d.Average, d.P90, d.Max, b.TrimmedMean} {
		if v <= 0 || math.IsNaN(v) || math.IsInf(v, 0) {
			return bad
		}
	}
	if math.IsNaN(d.Jitter) || math.IsInf(d.Jitter, 0) || d.Jitter < 0 || d.Min > d.Median || d.Median > d.P90 || d.P90 > d.Max || d.Average < d.Min || d.Average > d.Max || b.TrimmedMean < d.Min || b.TrimmedMean > d.Max {
		return bad
	}
	return nil
}
func desktopOrderedLatencyMeaning(position int) (role, kind, label, metric, endpoint string) {
	role = "intermediate"
	if position == 0 {
		role = "entry"
	}
	if position == 2 {
		role = "exit"
	}
	kind = "private-node"
	label = fmt.Sprintf("Cumulative path through node %d of 3", position+1)
	metric = "routed-private-response-including-connection"
	if position == 1 {
		kind = "public-path"
		label = "Cumulative path through custom node 2 of 3 → Cloudflare edge"
		metric = "routed-https-response-after-tls"
		endpoint = "https://" + hopmeasure.PublicHost + "/__down?bytes=1"
	}
	return
}
func decodeDesktopOrderedHistory(raw []byte) (desktopOrderedLatencyHistory, error) {
	var h desktopOrderedLatencyHistory
	bad := errors.New("invalid bounded ordered latency history")
	if len(raw) == 0 || len(raw) > desktopOrderedHistoryLimit || !utf8.Valid(raw) {
		return h, bad
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return h, bad
	}
	seen := map[string]bool{}
	var receipts []json.RawMessage
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return h, bad
		}
		seen[key] = true
		switch key {
		case "schema":
			if d.Decode(&h.Schema) != nil {
				return h, bad
			}
		case "receipts":
			if d.Decode(&receipts) != nil {
				return h, bad
			}
		default:
			return h, bad
		}
	}
	token, err = d.Token()
	if err != nil || token != json.Delim('}') || d.Decode(new(any)) != io.EOF || h.Schema != 1 || receipts == nil || len(receipts) > desktopOrderedHistoryEntries || len(seen) != 2 {
		return h, bad
	}
	h.Receipts = []hopmeasure.OrderedLatencyReceipt{}
	keys := map[string]bool{}
	for _, rawReceipt := range receipts {
		var r hopmeasure.OrderedLatencyReceipt
		if decodeRelayControlJSON(rawReceipt, &r) != nil {
			return h, bad
		}
		if err := validateDesktopOrderedReceipt(r, time.Now()); err != nil {
			return h, err
		}
		key := desktopOrderedReceiptKey(r)
		if keys[key] {
			return h, bad
		}
		keys[key] = true
		h.Receipts = append(h.Receipts, r)
	}
	return h, nil
}
func desktopOrderedHistoryPath(a *app) string {
	return filepath.Join(filepath.Dir(a.cfg.StateFile), "ordered-latency-history.json")
}
func readDesktopOrderedHistory(a *app) (desktopOrderedLatencyHistory, error) {
	raw, err := readPrivateRegular(desktopOrderedHistoryPath(a), desktopOrderedHistoryLimit)
	if errors.Is(err, os.ErrNotExist) {
		return desktopOrderedLatencyHistory{Schema: 1, Receipts: []hopmeasure.OrderedLatencyReceipt{}}, nil
	}
	if err != nil {
		return desktopOrderedLatencyHistory{}, err
	}
	return decodeDesktopOrderedHistory(raw)
}

type desktopOrderedHistoryPublication struct {
	path          string
	published     os.FileInfo
	before, after []byte
}

func (p *desktopOrderedHistoryPublication) current() error {
	before, err := os.Lstat(p.path)
	if err != nil || p.published == nil || !os.SameFile(p.published, before) {
		return errors.New("ordered history writer replaced")
	}
	raw, err := readPrivateRegular(p.path, desktopOrderedHistoryLimit)
	after, stat := os.Lstat(p.path)
	if err != nil || stat != nil || !os.SameFile(p.published, after) || !bytes.Equal(raw, p.after) {
		return errors.New("ordered history bytes replaced; newer writer retained")
	}
	return nil
}
func (p *desktopOrderedHistoryPublication) rollback() error {
	previous := p.before
	if previous == nil {
		previous = []byte("{\"schema\":1,\"receipts\":[]}\n")
	}
	_, err := atomicWritePrivateChecked(p.path, previous, p.current)
	return err
}

// Caller serializes the exact operation and cancellation through adoption.
// Every write has checked preimages, exact readback and own-inode rollback.
func saveDesktopOrderedHistory(a *app, r hopmeasure.OrderedLatencyReceipt, current func() error) error {
	if a == nil || current == nil {
		return errors.New("ordered history has no captured commit owner")
	}
	if err := validateDesktopOrderedReceipt(r, time.Now()); err != nil {
		return err
	}
	if err := current(); err != nil {
		return err
	}
	path := desktopOrderedHistoryPath(a)
	info, err := desktopComparisonCaptureFileInfo(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var before []byte
	h := desktopOrderedLatencyHistory{Schema: 1, Receipts: []hopmeasure.OrderedLatencyReceipt{}}
	if info != nil {
		before, err = readPrivateRegular(path, desktopOrderedHistoryLimit)
		if err != nil {
			return err
		}
		h, err = decodeDesktopOrderedHistory(before)
		if err != nil {
			return err
		}
	}
	rows := make([]hopmeasure.OrderedLatencyReceipt, 0, len(h.Receipts)+1)
	key := desktopOrderedReceiptKey(r)
	for _, old := range h.Receipts {
		if desktopOrderedReceiptKey(old) != key {
			rows = append(rows, old)
		}
	}
	rows = append(rows, r)
	if len(rows) > desktopOrderedHistoryEntries {
		rows = rows[len(rows)-desktopOrderedHistoryEntries:]
	}
	h.Receipts = rows
	after, err := json.Marshal(h)
	if err != nil || len(after) > desktopOrderedHistoryLimit {
		return errors.New("ordered history exceeds its private store bound")
	}
	check := func() error {
		if err := current(); err != nil {
			return err
		}
		if err := atomicWritePrivateTargetUnchanged(path, info); err != nil {
			return err
		}
		if info != nil {
			raw, err := readPrivateRegular(path, desktopOrderedHistoryLimit)
			if err != nil || !bytes.Equal(raw, before) {
				return errors.New("ordered history changed before commit")
			}
		}
		return nil
	}
	published, err := atomicWritePrivateChecked(path, after, check)
	if err != nil {
		return err
	}
	receipt := &desktopOrderedHistoryPublication{path: path, published: published, before: before, after: after}
	if err := receipt.current(); err != nil {
		return errors.Join(err, receipt.rollback())
	}
	if err := current(); err != nil {
		return errors.Join(err, receipt.rollback())
	}
	if err := receipt.current(); err != nil {
		return errors.Join(err, receipt.rollback())
	}
	return nil
}
