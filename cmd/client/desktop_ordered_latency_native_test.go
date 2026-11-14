package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"time"

	"router-vpn/internal/hopmeasure"
)

// Invoked by the existing installed Windows/Linux/Darwin positive typed
// scenarios. The caller supplies its original protected/local controller
// transport; no replacement VPN, profile, proxy or endpoint is constructed.
func desktopOrderedLatencyNativeRoundTrip(ctx context.Context, call func(context.Context, string, string, []byte) (int, []byte, error)) ([]hopmeasure.OrderedLatencyReceipt, error) {
	status, raw, err := call(ctx, http.MethodGet, "/api/speed-lab/ordered-latency", nil)
	var info desktopOrderedLatencyView
	if err != nil || status != 200 || decodeRelayControlJSON(raw, &info) != nil || info.Schema != 1 || len(info.Nodes) != 3 {
		return nil, errors.Join(err, errors.New("installed ordered fifty lacks its actual captured API"))
	}
	receipts := []hopmeasure.OrderedLatencyReceipt{}
	for position, node := range info.Nodes {
		nonce, err := randomHex(16)
		if err != nil {
			return nil, err
		}
		request := desktopOrderedLatencyRequest{Capture: info.Capture, NodeID: node.NodeID, Position: position, Request: nonce}
		if node.Position != position {
			return nil, errors.New("installed fifty node position changed")
		}
		// An apparently valid request with a substituted member cannot reach the
		// native mailbox or reuse another row's evidence.
		foreign := request
		foreign.NodeID = info.Nodes[(position+1)%3].NodeID
		body, _ := json.Marshal(foreign)
		code, _, err := call(ctx, http.MethodPost, "/api/speed-lab/ordered-latency", body)
		if err != nil || code != 409 {
			return nil, errors.Join(err, errors.New("installed fifty admitted foreign member"))
		}
		body, _ = json.Marshal(request)
		code, raw, err := call(ctx, http.MethodPost, "/api/speed-lab/ordered-latency", body)
		if err != nil || code != 202 {
			return nil, errors.Join(err, fmt.Errorf("installed fifty start refused: %d %s", code, raw))
		}
		ticker := time.NewTicker(20 * time.Millisecond)
		var view desktopOrderedLatencyView
		for {
			code, raw, err = call(ctx, http.MethodGet, "/api/speed-lab/ordered-latency?request_id="+nonce, nil)
			if err != nil || code != 200 || decodeRelayControlJSON(raw, &view) != nil || view.Schema != 1 || view.desktopOrderedLatencyRequest != request {
				ticker.Stop()
				return nil, errors.Join(err, errors.New("installed fifty lost its original request/capture"))
			}
			if view.Status.Complete && view.Status.Drained {
				break
			}
			select {
			case <-ctx.Done():
				ticker.Stop()
				return nil, ctx.Err()
			case <-ticker.C:
			}
		}
		ticker.Stop()
		if view.Status.Stage != "complete" || view.Status.Failure != "" || view.Receipt == nil || len(view.Status.Results) != 1 || !reflect.DeepEqual(view.Status.Results[0], view.Receipt.Result) {
			return nil, errors.New("installed fifty did not durably adopt its exact joined native receipt")
		}
		saved := *view.Receipt
		if validateDesktopOrderedReceipt(saved, time.Now()) != nil || saved.Request != nonce || saved.NodeID != node.NodeID || saved.Position != position || saved.SourceSHA256 != info.Capture.SourceSHA256 || saved.ConfigSHA256 != info.Capture.ConfigSHA256 || saved.GenerationSHA256 != info.Capture.GenerationSHA256 {
			return nil, errors.New("installed fifty saved a foreign/partial result")
		}
		receipts = append(receipts, saved)
	}
	code, raw, err := call(ctx, http.MethodGet, "/api/speed-lab/ordered-latency", nil)
	var reloaded desktopOrderedLatencyView
	if err != nil || code != 200 || decodeRelayControlJSON(raw, &reloaded) != nil || reloaded.Capture != info.Capture {
		return nil, errors.Join(err, errors.New("installed fifty durable readback changed owner"))
	}
	for _, receipt := range receipts {
		found := false
		for _, saved := range reloaded.History {
			if reflect.DeepEqual(receipt, saved) {
				found = true
			}
		}
		if !found {
			return nil, errors.New("installed fifty omitted its exact durable historical receipt")
		}
	}
	return receipts, nil
}
