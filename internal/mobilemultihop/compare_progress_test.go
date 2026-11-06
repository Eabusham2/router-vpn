package mobilemultihop

import (
	"encoding/json"
	"net/http"
	"router-vpn/internal/routechoice"
	"sync"
	"testing"
)

func TestCompareProgressRetiresOnlyOriginalFailedActivation(t *testing.T) {
	for _, mode := range []string{"original", "foreign-candidate", "foreign-result", "retired-generation", "completed", "eligible", "zero-score", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			c := &Controller{meta: Metadata{EntryID: "entry", ExitID: "exit", ExitMode: "shadowsocks"}}
			c.generation.Store(1)
			local, server := c.candidate(routechoice.Local), c.candidate(routechoice.Server)
			score := 4.0
			c.progress.Measurements = []routechoice.Measurement{{Candidate: local, Eligible: true, ScoreMS: &score}, {Candidate: server, Eligible: true, ScoreMS: &score}}
			failed := routechoice.Measurement{Candidate: local, Failure: "final probe refused"}
			event := routechoice.Event{Stage: "activation-failed", Candidate: local, Result: &failed}
			switch mode {
			case "foreign-candidate":
				event.Candidate.EntryID = "other"
			case "foreign-result":
				failed.Candidate = server
			case "retired-generation":
				c.generation.Store(2)
			case "completed":
				c.progress.Complete = true
			case "eligible":
				failed.Eligible = true
			case "zero-score":
				zero := 0.0
				failed.ScoreMS = &zero
			case "unknown":
				c.progress.Measurements = c.progress.Measurements[1:]
			}
			c.event(event)
			for _, row := range c.progress.Measurements {
				wantInvalid := mode == "original" && row.Candidate == local
				if wantInvalid {
					if row.Eligible || row.ScoreMS != nil || row.Failure == "" {
						t.Fatal("failed final retained score")
					}
				} else if !row.Eligible || row.ScoreMS == nil || *row.ScoreMS != 4 {
					t.Fatal("unrelated or retired progress mutated")
				}
			}
		})
	}
}

func TestCompareProgressShippingFinalFailure(t *testing.T) {
	previous := Targets
	Targets = []string{"http://1.1.1.1/public-a", "http://1.0.0.1/public-b"}
	defer func() { Targets = previous }()
	r, e := externalExecutionRequest(t, "auto", "")
	var mu sync.Mutex
	failedTag := ""
	for _, tag := range []string{LocalTag, ServerTag} {
		original := e.node[tag].Config.Handler
		e.node[tag].Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
			e.mu.Lock()
			count := e.nodeCalls[tag]
			e.mu.Unlock()
			mu.Lock()
			reject := count > 0 && failedTag == ""
			if reject {
				failedTag = tag
			}
			mu.Unlock()
			if reject {
				http.Error(w, "independent final activation refused", 503)
				return
			}
			original.ServeHTTP(w, q)
		})
	}
	if _, err := r.Run(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	failed := failedTag
	mu.Unlock()
	if failed == "" {
		t.Fatal("no final reactivation witnessed")
	}
	var progress Progress
	if json.Unmarshal([]byte(r.ProgressJSON()), &progress) != nil {
		t.Fatal("missing progress")
	}
	failedExecution := "local"
	if failed == ServerTag {
		failedExecution = "server"
	}
	if r.Execution() == failedExecution {
		t.Fatal("failed winner adopted")
	}
	var found bool
	for _, m := range progress.Measurements {
		if string(m.Candidate.Execution) == failedExecution {
			found = true
			if m.Eligible || m.ScoreMS != nil || m.Failure == "" {
				t.Fatal("shipping callback retained failed activation score", progress)
			}
		} else if !m.Eligible || m.ScoreMS == nil {
			t.Fatal("surviving candidate erased")
		}
	}
	if !found {
		t.Fatal("failed candidate receipt erased")
	}
}

func TestCompareProgressShippingCancellationRetiresPartialScores(t *testing.T) {
	previous := Targets
	Targets = []string{"http://1.1.1.1/public-a", "http://1.0.0.1/public-b"}
	defer func() { Targets = previous }()
	r, e := externalExecutionRequest(t, "auto", "")
	e.onNode = func(tag string) {
		e.mu.Lock()
		count := e.nodeCalls[tag]
		e.mu.Unlock()
		if count > 1 {
			r.Cancel()
		}
	}
	if _, err := r.Run(); err == nil {
		t.Fatal("cancelled final activation passed")
	}
	var progress Progress
	if json.Unmarshal([]byte(r.ProgressJSON()), &progress) != nil || !progress.Complete || progress.Stage != "failed" || len(progress.Measurements) != 2 {
		t.Fatal("missing terminal cancelled comparison", r.ProgressJSON())
	}
	for _, m := range progress.Measurements {
		if m.Eligible || m.ScoreMS != nil {
			t.Fatal("cancelled comparison retained eligible score")
		}
	}
}

func TestCompareProgressCompletedHistoryRemainsImmutable(t *testing.T) {
	c := &Controller{}
	score := 2.0
	c.progress = Progress{Complete: true, Stage: "selected", Execution: "local", Measurements: []routechoice.Measurement{{Eligible: true, ScoreMS: &score}}}
	c.failed("selected lease later expired")
	if c.progress.Stage != "failed" || !c.progress.Measurements[0].Eligible || c.progress.Measurements[0].ScoreMS != &score {
		t.Fatal("completed historical comparison rewritten")
	}
}
