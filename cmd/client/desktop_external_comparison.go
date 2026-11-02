package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"router-vpn/internal/hopmeasure"
)

const desktopExternalComparisonMetric = "routed-https-response-after-tls"
const desktopExternalComparisonNote = "Each saved external path keeps its own saved entry, DNS and protection. Every valid path supplies 50 HTTPS response times through the proved exit to the same Cloudflare endpoint; timing starts after TLS. Fastest is the lowest 10% trimmed mean. This is separate from Router TCP reachability."

type desktopExternalComparisonRequest struct {
	Request        string `json:"request_id"`
	Cohort         string `json:"cohort_id"`
	ConnectFastest bool   `json:"connect_fastest"`
}

type desktopExternalComparisonRow struct {
	ID            string                       `json:"id"`
	Name          string                       `json:"name"`
	Protocol      string                       `json:"protocol"`
	EntryID       string                       `json:"entry_id,omitempty"`
	EntryName     string                       `json:"entry_name,omitempty"`
	EntryMode     string                       `json:"entry_mode,omitempty"`
	Status        string                       `json:"status"`
	Failure       string                       `json:"failure,omitempty"`
	SourceToken   string                       `json:"source_token"`
	SourceSHA256  string                       `json:"source_sha256,omitempty"`
	ConfigSHA256  string                       `json:"config_sha256,omitempty"`
	NetworkSHA256 string                       `json:"network_sha256,omitempty"`
	Execution     string                       `json:"execution,omitempty"`
	MeasuredAt    int64                        `json:"measured_at,omitempty"`
	Benchmark     *hopmeasure.LatencyBenchmark `json:"benchmark,omitempty"`
}

type desktopExternalComparisonView struct {
	Request        string                         `json:"request_id"`
	Cohort         string                         `json:"cohort_id"`
	ConnectFastest bool                           `json:"connect_fastest"`
	Stage          string                         `json:"stage"`
	Complete       bool                           `json:"complete"`
	Drained        bool                           `json:"drained"`
	Restored       bool                           `json:"restored"`
	Committed      bool                           `json:"committed"`
	WinnerID       string                         `json:"winner_id,omitempty"`
	CurrentID      string                         `json:"current_id,omitempty"`
	Progress       string                         `json:"progress,omitempty"`
	Failure        string                         `json:"failure,omitempty"`
	Warning        string                         `json:"warning,omitempty"`
	Rows           []desktopExternalComparisonRow `json:"rows"`
	Note           string                         `json:"note"`
}

type desktopExternalComparisonOffer struct {
	request desktopExternalComparisonRequest
	expires time.Time
}

type desktopExternalComparisonSlot struct {
	mu      sync.Mutex
	offer   *desktopExternalComparisonOffer
	current *desktopExternalComparisonOperation
}

type desktopExternalComparisonOperation struct {
	mu                sync.Mutex
	cleanupMu         sync.Mutex
	cleanupNetwork    desktopExternalComparisonNetwork
	cleanupWasDrained bool
	request           desktopExternalComparisonRequest
	view              desktopExternalComparisonView
	latency           *desktopLatencyOperation
	cancel            context.CancelFunc
	done              chan struct{}
}

func (a *app) desktopExternalComparisonFor() *desktopExternalComparisonSlot {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.externalComparisons == nil {
		a.externalComparisons = &desktopExternalComparisonSlot{}
	}
	return a.externalComparisons
}

func readDesktopExternalComparisonRequest(w http.ResponseWriter, r *http.Request) (desktopExternalComparisonRequest, error) {
	var request desktopExternalComparisonRequest
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil || decodeRelayControlJSON(raw, &request) != nil || !desktopMTURequestPattern.MatchString(request.Request) || !desktopMTUPathPattern.MatchString(request.Cohort) {
		return request, errors.New("the current external comparison request and saved-source cohort are required")
	}
	return request, nil
}

func desktopComparisonPending(operation *desktopExternalComparisonOperation) bool {
	if operation == nil {
		return false
	}
	select {
	case <-operation.done:
		operation.mu.Lock()
		pending := operation.cleanupNetwork != nil
		operation.mu.Unlock()
		return pending
	default:
		return true
	}
}

func (a *app) desktopExternalComparison(w http.ResponseWriter, r *http.Request) {
	slot := a.desktopExternalComparisonFor()
	if r.Method == http.MethodGet {
		if request := r.URL.Query().Get("request_id"); request != "" {
			slot.mu.Lock()
			operation := slot.current
			slot.mu.Unlock()
			if operation == nil || operation.request.Request != request || !desktopMTURequestPattern.MatchString(request) {
				http.Error(w, "external comparison was replaced or is unknown", http.StatusConflict)
				return
			}
			writeDesktopLatencyJSON(w, http.StatusOK, operation.snapshot())
			return
		}
		a.mu.Lock()
		store := cloneRouterProfileStore(a.profiles)
		a.mu.Unlock()
		cohort, err := desktopComparisonCatalogToken(store)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		request, err := randomHex(16)
		if err != nil {
			http.Error(w, "cannot allocate an external comparison request", http.StatusInternalServerError)
			return
		}
		slot.mu.Lock()
		if desktopComparisonPending(slot.current) {
			operation := slot.current
			slot.mu.Unlock()
			writeDesktopLatencyJSON(w, http.StatusConflict, operation.snapshot())
			return
		}
		// One short-lived, single-use offer replaces old UI intent. Cancel before
		// POST consumes it too; no unbounded/lifetime-exhausting nonce history.
		slot.offer = &desktopExternalComparisonOffer{request: desktopExternalComparisonRequest{Request: request, Cohort: cohort}, expires: time.Now().Add(2 * time.Minute)}
		slot.mu.Unlock()
		rows := []map[string]any{}
		for _, p := range store.Profiles {
			if p.NodeKind == "external" && p.External != nil {
				rows = append(rows, map[string]any{"id": p.ID, "name": p.Name, "protocol": p.External.Protocol, "entry_id": p.MultihopEntryID,
					"has_entry": p.MultihopEnabled, "requested_execution": p.MultihopExecution})
			}
		}
		history, historyErr := readDesktopExternalComparisonHistory(a)
		warning := ""
		if historyErr != nil {
			warning = "Saved external-path statistics could not be read; they have not been replaced."
		}
		writeDesktopLatencyJSON(w, http.StatusOK, map[string]any{"request_id": request, "cohort_id": cohort, "expires_in_ms": 120000,
			"candidates": rows, "history": history, "warning": warning, "note": desktopExternalComparisonNote})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "GET or POST only", http.StatusMethodNotAllowed)
		return
	}
	request, err := readDesktopExternalComparisonRequest(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	slot.mu.Lock()
	offer := slot.offer
	if desktopComparisonPending(slot.current) || offer == nil || offer.request.Request != request.Request || offer.request.Cohort != request.Cohort || !time.Now().Before(offer.expires) || r.Context().Err() != nil {
		slot.mu.Unlock()
		http.Error(w, "external comparison request expired, was cancelled, or has another owner", http.StatusConflict)
		return
	}
	slot.offer = nil
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Hour)
	operation := &desktopExternalComparisonOperation{request: request, cancel: cancel, done: make(chan struct{}), view: desktopExternalComparisonView{
		Request: request.Request, Cohort: request.Cohort, ConnectFastest: request.ConnectFastest, Stage: "capturing", Restored: true, Drained: true, Rows: []desktopExternalComparisonRow{}, Note: desktopExternalComparisonNote}}
	slot.current = operation
	slot.mu.Unlock()
	go a.runDesktopExternalComparison(ctx, operation)
	writeDesktopLatencyJSON(w, http.StatusAccepted, operation.snapshot())
}

func (a *app) cancelDesktopExternalComparison(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	request, err := readDesktopExternalComparisonRequest(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	slot := a.desktopExternalComparisonFor()
	slot.mu.Lock()
	operation := slot.current
	if operation != nil && operation.request.Request == request.Request && operation.request.Cohort == request.Cohort {
		slot.mu.Unlock()
		operation.cancel()
		select {
		case <-operation.done:
			if err := operation.finishNetworkCleanup(); err != nil {
				http.Error(w, "captured network observer cleanup is still pending; retry Cancel", http.StatusServiceUnavailable)
				return
			}
		default:
		}
		writeDesktopLatencyJSON(w, http.StatusAccepted, operation.snapshot())
		return
	}
	if offer := slot.offer; offer != nil && offer.request.Request == request.Request && offer.request.Cohort == request.Cohort {
		slot.offer = nil
		slot.mu.Unlock()
		writeDesktopLatencyJSON(w, http.StatusAccepted, desktopExternalComparisonView{Request: request.Request, Cohort: request.Cohort, Stage: "cancelled", Complete: true, Drained: true, Restored: true, Rows: []desktopExternalComparisonRow{}, Note: desktopExternalComparisonNote})
		return
	}
	slot.mu.Unlock()
	http.Error(w, "external comparison cancellation belongs to another request", http.StatusConflict)
}

func (o *desktopExternalComparisonOperation) retainNetworkCleanup(network desktopExternalComparisonNetwork) error {
	o.mu.Lock()
	o.cleanupNetwork, o.cleanupWasDrained = network, o.view.Drained
	o.mu.Unlock()
	return o.finishNetworkCleanup()
}

func (o *desktopExternalComparisonOperation) finishNetworkCleanup() error {
	o.cleanupMu.Lock()
	defer o.cleanupMu.Unlock()
	o.mu.Lock()
	network := o.cleanupNetwork
	o.mu.Unlock()
	if network == nil {
		return nil
	}
	err := network.Close()
	o.mu.Lock()
	defer o.mu.Unlock()
	const pending = "The captured network observer has unresolved cleanup or final validation. Retry Cancel; another external comparison remains blocked."
	if err != nil {
		o.view.Drained = false
		if !strings.Contains(o.view.Warning, pending) {
			if o.view.Warning != "" {
				o.view.Warning += " "
			}
			o.view.Warning += pending
		}
		return err
	}
	o.cleanupNetwork = nil
	o.view.Drained = o.cleanupWasDrained
	o.view.Warning = strings.Replace(o.view.Warning, pending, "Captured network observer cleanup is complete.", 1)
	return nil
}

func (a *app) finishDesktopExternalComparisonCleanup() error {
	a.mu.Lock()
	slot := a.externalComparisons
	a.mu.Unlock()
	if slot == nil {
		return nil
	}
	slot.mu.Lock()
	operation := slot.current
	slot.mu.Unlock()
	if operation == nil {
		return nil
	}
	operation.cancel()
	select {
	case <-operation.done:
		return operation.finishNetworkCleanup()
	default:
		return errors.New("external comparison still owns its temporary transaction")
	}
}

func (o *desktopExternalComparisonOperation) snapshot() desktopExternalComparisonView {
	o.mu.Lock()
	view, latency := o.view, o.latency
	view.Rows = append([]desktopExternalComparisonRow{}, view.Rows...)
	for i := range view.Rows {
		view.Rows[i].Benchmark = cloneDesktopComparisonBenchmark(view.Rows[i].Benchmark)
	}
	o.mu.Unlock()
	if latency != nil {
		latency.mu.Lock()
		view.Progress = latency.status.Stage
		latency.mu.Unlock()
	}
	return view
}

func cloneDesktopComparisonBenchmark(source *hopmeasure.LatencyBenchmark) *hopmeasure.LatencyBenchmark {
	if source == nil {
		return nil
	}
	result := *source
	if source.Distribution != nil {
		distribution := *source.Distribution
		result.Distribution = &distribution
	}
	return &result
}

func (o *desktopExternalComparisonOperation) stage(stage, id string) {
	o.mu.Lock()
	o.view.Stage, o.view.CurrentID = stage, id
	o.mu.Unlock()
}

func (o *desktopExternalComparisonOperation) measuring(operation *desktopLatencyOperation) {
	o.mu.Lock()
	o.latency = operation
	o.mu.Unlock()
}

func (o *desktopExternalComparisonOperation) warn(message string) {
	o.mu.Lock()
	if o.view.Warning == "" {
		o.view.Warning = message
	} else {
		o.view.Warning += " " + message
	}
	o.mu.Unlock()
}
