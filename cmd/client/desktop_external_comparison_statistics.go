package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"sort"
	"time"

	"router-vpn/internal/hopmeasure"
)

type desktopExternalComparisonHistory struct {
	Schema int                            `json:"schema"`
	Rows   []desktopExternalComparisonRow `json:"rows"`
}

func desktopComparisonHistoryPath(a *app) string {
	return filepath.Join(filepath.Dir(a.cfg.ProfilesFile), "external-path-statistics.json")
}

func validDesktopComparisonBenchmark(b *hopmeasure.LatencyBenchmark) bool {
	if b == nil || b.Schema != 1 || b.Measurement != desktopExternalComparisonMetric || b.Endpoint != "https://"+hopmeasure.PublicHost+"/__down?bytes=1" ||
		b.Attempts != 50 || b.Failed != 0 || b.Distribution == nil || b.Distribution.Samples != 50 {
		return false
	}
	d := b.Distribution
	// The native service sums 50 binary floating-point durations (40 after
	// trimming). Even identical samples can put the arithmetic mean a few ulps
	// outside their exact minimum/maximum. Bound only this arithmetic roundoff;
	// using the preceding representable value keeps the allowance finite even
	// when a malformed input supplies the largest finite float.
	roundoff := 64 * (d.Max - math.Nextafter(d.Max, 0))
	for _, value := range []float64{d.Min, d.Median, d.Average, d.P90, d.Max, b.TrimmedMean} {
		if math.IsNaN(value) || math.IsInf(value, 0) || value <= 0 ||
			(value < d.Min && d.Min-value > roundoff) || (value > d.Max && value-d.Max > roundoff) {
			return false
		}
	}
	span := d.Max - d.Min
	return d.Min <= d.Median && d.Median <= d.P90 && d.P90 <= d.Max && !math.IsNaN(d.Jitter) && !math.IsInf(d.Jitter, 0) && d.Jitter >= 0 && (d.Jitter <= span || d.Jitter-span <= roundoff)
}

func desktopComparisonHistoryRowValid(row desktopExternalComparisonRow, now time.Time) bool {
	return validProfileID(row.ID) && (row.EntryID == "" || validProfileID(row.EntryID)) && len(row.Name) <= 512 && len(row.EntryName) <= 512 &&
		len(row.Protocol) <= 64 && len(row.EntryMode) <= 64 && row.Status == "complete" && row.Failure == "" &&
		desktopMTUPathPattern.MatchString(row.SourceToken) && desktopMTUPathPattern.MatchString(row.SourceSHA256) &&
		desktopMTUPathPattern.MatchString(row.ConfigSHA256) && desktopMTUPathPattern.MatchString(row.NetworkSHA256) &&
		(row.Execution == "local" || row.Execution == "server") && row.MeasuredAt > 0 && row.MeasuredAt <= now.Add(time.Minute).UnixMilli() && validDesktopComparisonBenchmark(row.Benchmark)
}

func decodeDesktopComparisonHistory(raw []byte) (desktopExternalComparisonHistory, error) {
	history := desktopExternalComparisonHistory{Schema: 1, Rows: []desktopExternalComparisonRow{}}
	if decodeRelayControlJSON(raw, &history) != nil || history.Schema != 1 || history.Rows == nil || len(history.Rows) > 512 {
		return desktopExternalComparisonHistory{}, errors.New("saved external-path statistics are malformed")
	}
	seen := map[string]bool{}
	for _, row := range history.Rows {
		key := row.ID + ":" + row.SourceToken
		if seen[key] || !desktopComparisonHistoryRowValid(row, time.Now()) {
			return desktopExternalComparisonHistory{}, errors.New("saved external-path statistics have invalid provenance or incomplete measurements")
		}
		seen[key] = true
	}
	return history, nil
}

func readDesktopExternalComparisonHistory(a *app) (desktopExternalComparisonHistory, error) {
	raw, err := readPrivateRegular(desktopComparisonHistoryPath(a), 2<<20)
	defer clear(raw)
	if errors.Is(err, os.ErrNotExist) {
		return desktopExternalComparisonHistory{Schema: 1, Rows: []desktopExternalComparisonRow{}}, nil
	}
	if err != nil {
		return desktopExternalComparisonHistory{}, err
	}
	return decodeDesktopComparisonHistory(raw)
}

// History remains provisional through the batch's final cohort check. Keep the
// exact published image so a later failure can restore only our own write.
type desktopComparisonHistoryReceipt struct {
	path          string
	published     os.FileInfo
	before, after []byte
}

func (r *desktopComparisonHistoryReceipt) clear() {
	if r != nil {
		clear(r.before)
		clear(r.after)
	}
}

func (r *desktopComparisonHistoryReceipt) current() error {
	if r == nil || r.published == nil {
		return errors.New("external history has no publication receipt")
	}
	info, err := os.Lstat(r.path)
	if err != nil || !desktopComparisonSameFile(r.published, info) {
		return errors.New("external history publication was replaced; newer writer retained")
	}
	raw, err := readPrivateRegular(r.path, 2<<20)
	equal := err == nil && bytes.Equal(r.after, raw)
	clear(raw)
	if !equal {
		return errors.New("external history publication changed; newer writer retained")
	}
	return nil
}

func (r *desktopComparisonHistoryReceipt) rollback() error {
	if r == nil {
		return nil
	}
	if err := r.current(); err != nil {
		return err
	}
	previous := r.before
	if previous == nil {
		// Keep a valid empty sidecar when none existed. A checked atomic
		// replacement avoids a pathname unlink of a possible newer writer.
		previous = []byte("{\"schema\":1,\"rows\":[]}\n")
	}
	_, err := atomicWritePrivateChecked(r.path, previous, r.current)
	return err
}

func saveDesktopExternalComparisonHistory(a *app, rows []desktopExternalComparisonRow, current func() error) (*desktopComparisonHistoryReceipt, error) {
	if current == nil || current() != nil {
		return nil, errors.New("external comparison history lost its completed cohort")
	}
	path := desktopComparisonHistoryPath(a)
	before, statErr := desktopComparisonCaptureFileInfo(path)
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return nil, statErr
	}
	var original []byte
	history := desktopExternalComparisonHistory{Schema: 1, Rows: []desktopExternalComparisonRow{}}
	if before != nil {
		var err error
		original, err = readPrivateRegular(path, 2<<20)
		defer clear(original)
		if err != nil {
			return nil, err
		}
		history, err = decodeDesktopComparisonHistory(original)
		if err != nil {
			return nil, err
		} // A corrupt sidecar is visible and never overwritten.
	}
	bySource := map[string]desktopExternalComparisonRow{}
	for _, row := range history.Rows {
		bySource[row.ID+":"+row.SourceToken] = row
	}
	for _, row := range rows {
		if row.Benchmark == nil {
			continue
		}
		if !desktopComparisonHistoryRowValid(row, time.Now()) {
			return nil, errors.New("external comparison history refuses an invalid score")
		}
		row.Benchmark = cloneDesktopComparisonBenchmark(row.Benchmark)
		bySource[row.ID+":"+row.SourceToken] = row
	}
	history.Rows = []desktopExternalComparisonRow{}
	for _, row := range bySource {
		history.Rows = append(history.Rows, row)
	}
	sort.Slice(history.Rows, func(i, j int) bool {
		if history.Rows[i].MeasuredAt != history.Rows[j].MeasuredAt {
			return history.Rows[i].MeasuredAt > history.Rows[j].MeasuredAt
		}
		return history.Rows[i].ID+history.Rows[i].SourceToken < history.Rows[j].ID+history.Rows[j].SourceToken
	})
	if len(history.Rows) > 512 {
		history.Rows = history.Rows[:512]
	}
	raw, err := json.MarshalIndent(history, "", "  ")
	if err != nil || len(raw) > 2<<20 {
		return nil, errors.New("external comparison history exceeds its bounded private store")
	}
	defer clear(raw)
	check := func() error {
		if err := current(); err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if before == nil {
			if !errors.Is(err, os.ErrNotExist) {
				return errors.New("another writer created external-path history")
			}
			return nil
		}
		if err != nil || !desktopComparisonSameFile(before, info) {
			return errors.New("external-path history was replaced")
		}
		readback, err := readPrivateRegular(path, 2<<20)
		equal := err == nil && bytes.Equal(original, readback)
		clear(readback)
		if !equal {
			return errors.New("external-path history changed")
		}
		return nil
	}
	raw = append(raw, '\n')
	published, err := atomicWritePrivateChecked(path, raw, check)
	if err != nil {
		return nil, err
	}
	receipt := &desktopComparisonHistoryReceipt{path: path, published: published, before: append([]byte(nil), original...), after: append([]byte(nil), raw...)}
	if err := receipt.current(); err != nil {
		return receipt, err
	}
	return receipt, current()
}
