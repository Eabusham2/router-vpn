package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"router-vpn/internal/hopmeasure"
)

type desktopSelectedLatencyHistoryRecord struct {
	Capture string                           `json:"selected_capture"`
	Receipt hopmeasure.OrderedLatencyReceipt `json:"receipt"`
}

type desktopSelectedLatencyHistory struct {
	Schema  int                                   `json:"schema"`
	Records []desktopSelectedLatencyHistoryRecord `json:"records"`
}

func desktopSelectedLatencyHistoryPath(a *app) string {
	return filepath.Join(filepath.Dir(a.cfg.StateFile), "selected-ordered-latency-history.json")
}

func desktopSelectedLatencyHistoryKey(row desktopSelectedLatencyHistoryRecord) (string, error) {
	capture, _, err := decodeDesktopSelectedLatencyCapture(row.Capture)
	if err != nil {
		return "", err
	}
	return capture.Execution + ":" + desktopOrderedReceiptKey(row.Receipt), nil
}

func decodeDesktopSelectedLatencyHistory(raw []byte) (desktopSelectedLatencyHistory, error) {
	var history desktopSelectedLatencyHistory
	bad := errors.New("invalid bounded selected latency history")
	if len(raw) == 0 || len(raw) > desktopOrderedHistoryLimit || decodePrivateControlJSONBounded(raw, &history, desktopOrderedHistoryLimit) != nil ||
		history.Schema != 1 || history.Records == nil || len(history.Records) > desktopOrderedHistoryEntries {
		return history, bad
	}
	keys := map[string]bool{}
	for _, row := range history.Records {
		if err := validateDesktopSelectedLatencyReceipt(row.Capture, row.Receipt, time.Now()); err != nil {
			return history, err
		}
		key, err := desktopSelectedLatencyHistoryKey(row)
		if err != nil || keys[key] {
			return history, bad
		}
		keys[key] = true
	}
	return history, nil
}

func readDesktopSelectedLatencyHistory(a *app) (desktopSelectedLatencyHistory, error) {
	raw, err := readPrivateRegular(desktopSelectedLatencyHistoryPath(a), desktopOrderedHistoryLimit)
	if errors.Is(err, os.ErrNotExist) {
		return desktopSelectedLatencyHistory{Schema: 1, Records: []desktopSelectedLatencyHistoryRecord{}}, nil
	}
	if err != nil {
		return desktopSelectedLatencyHistory{}, err
	}
	return decodeDesktopSelectedLatencyHistory(raw)
}

func readDesktopOrderedLatencyViewHistory(a *app, view desktopOrderedLatencyView) ([]hopmeasure.OrderedLatencyReceipt, error) {
	var receipts []hopmeasure.OrderedLatencyReceipt
	if view.Capture.SelectedCaptureJSON == "" {
		history, err := readDesktopOrderedHistory(a)
		if err != nil {
			return nil, err
		}
		receipts = history.Receipts
	} else {
		selected, nodes, err := decodeDesktopSelectedLatencyCapture(view.Capture.SelectedCaptureJSON)
		if err != nil || !reflect.DeepEqual(nodes, view.Nodes) {
			return nil, errors.New("selected history lost its complete current inventory")
		}
		history, err := readDesktopSelectedLatencyHistory(a)
		if err != nil {
			return nil, err
		}
		for _, row := range history.Records {
			old, oldNodes, err := decodeDesktopSelectedLatencyCapture(row.Capture)
			if err != nil {
				return nil, err
			}
			// History may be from an earlier generation, but never from another
			// choice, source, configuration, node inventory or timing meaning.
			if old.Execution == selected.Execution && old.SourceSHA256 == selected.SourceSHA256 &&
				old.ConfigSHA256 == selected.ConfigSHA256 && reflect.DeepEqual(oldNodes, nodes) {
				receipts = append(receipts, row.Receipt)
			}
		}
	}
	matched := []hopmeasure.OrderedLatencyReceipt{}
	for _, saved := range receipts {
		if saved.SourceSHA256 == view.Capture.SourceSHA256 && saved.ConfigSHA256 == view.Capture.ConfigSHA256 &&
			saved.Position >= 0 && saved.Position < len(view.Nodes) && desktopOrderedReceiptMatchesNode(saved, view.Nodes[saved.Position]) {
			matched = append(matched, saved)
		}
	}
	return matched, nil
}

func saveDesktopOrderedCapturedHistory(a *app, capture desktopOrderedLatencyCapture, receipt hopmeasure.OrderedLatencyReceipt, current func() error) error {
	if capture.SelectedCaptureJSON == "" {
		return saveDesktopOrderedHistory(a, receipt, current)
	}
	if a == nil || current == nil || validateDesktopSelectedLatencyCaptureBinding(capture) != nil ||
		validateDesktopSelectedLatencyReceipt(capture.SelectedCaptureJSON, receipt, time.Now()) != nil {
		return errors.New("selected history has no original complete receipt and commit owner")
	}
	if err := current(); err != nil {
		return err
	}
	path := desktopSelectedLatencyHistoryPath(a)
	info, err := desktopComparisonCaptureFileInfo(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var before []byte
	history := desktopSelectedLatencyHistory{Schema: 1, Records: []desktopSelectedLatencyHistoryRecord{}}
	if info != nil {
		before, err = readPrivateRegular(path, desktopOrderedHistoryLimit)
		if err != nil {
			return err
		}
		history, err = decodeDesktopSelectedLatencyHistory(before)
		if err != nil {
			return err
		}
	}
	row := desktopSelectedLatencyHistoryRecord{Capture: capture.SelectedCaptureJSON, Receipt: receipt}
	key, err := desktopSelectedLatencyHistoryKey(row)
	if err != nil {
		return err
	}
	rows := make([]desktopSelectedLatencyHistoryRecord, 0, len(history.Records)+1)
	for _, old := range history.Records {
		oldKey, err := desktopSelectedLatencyHistoryKey(old)
		if err != nil {
			return err
		}
		if oldKey != key {
			rows = append(rows, old)
		}
	}
	rows = append(rows, row)
	if len(rows) > desktopOrderedHistoryEntries {
		rows = rows[len(rows)-desktopOrderedHistoryEntries:]
	}
	history.Records = rows
	after, err := json.Marshal(history)
	if err != nil || len(after) > desktopOrderedHistoryLimit {
		return errors.New("selected history exceeds its private store bound")
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
				return errors.New("selected history changed before commit")
			}
		}
		return nil
	}
	published, err := atomicWritePrivateChecked(path, after, check)
	if err != nil {
		return err
	}
	publication := &desktopOrderedHistoryPublication{path: path, published: published, before: before, after: after,
		empty: []byte("{\"schema\":1,\"records\":[]}\n")}
	if err := publication.current(); err != nil {
		return errors.Join(err, publication.rollback())
	}
	if err := current(); err != nil {
		return errors.Join(err, publication.rollback())
	}
	if err := publication.current(); err != nil {
		return errors.Join(err, publication.rollback())
	}
	return nil
}
