package linuxprotection

import (
	"errors"

	"router-vpn/internal/mobiletor"
)

// JournalPreparation records the accepted captured policy and original engine
// before the parent creates any per-session nft table. Created is appended
// only after the retained creator supplies its exclusive native receipt. This
// is durable comparison data, never a recovery or table-adoption capability.
type JournalPreparation struct {
	Capture      mobiletor.DesktopSocketCapture            `json:"capture"`
	HomeLAN      bool                                      `json:"home_lan"`
	ConfigSHA256 string                                    `json:"config_sha256"`
	Policy       string                                    `json:"policy"`
	Engine       ProcessRecord                             `json:"engine"`
	Created      *mobiletor.DesktopLinuxNodeCreationRecord `json:"created,omitempty"`
}

func (p JournalPreparation) Validate(owner ParentRecord) error {
	if !lowerHex(p.Capture.SessionID, 32) || !lowerHex(p.Capture.SourceSHA256, 64) || !lowerHex(p.Capture.NetworkID, 32) ||
		!lowerHex(p.ConfigSHA256, 64) || (p.Policy != "always" && p.Policy != "on-connect") ||
		p.Engine.Validate() != nil || !processBelongsToParent(p.Engine, owner) {
		return errors.New("Linux prepare intent lost its selected capture or original native engine")
	}
	if p.Created != nil && (p.Created.Validate() != nil || p.Created.Capture != p.Capture || p.Created.HomeLAN != p.HomeLAN) {
		return errors.New("Linux prepare intent substituted its original creation receipt")
	}
	return nil
}

func clonePreparation(p *JournalPreparation) *JournalPreparation {
	if p == nil {
		return nil
	}
	copy := *p
	if p.Created != nil {
		created := *p.Created
		copy.Created = &created
	}
	return &copy
}

func samePreparation(a, b *JournalPreparation, receipt bool) bool {
	if a == nil || b == nil {
		return a == b
	}
	first, second := *a, *b
	first.Created, second.Created = nil, nil
	return first == second && (!receipt || (a.Created == nil && b.Created == nil) ||
		(a.Created != nil && b.Created != nil && *a.Created == *b.Created))
}

func preparationMatchesCandidate(p *JournalPreparation, candidate JournalState) bool {
	return p != nil && p.Created != nil && candidate.Target != nil && candidate.Engine != nil &&
		*candidate.Engine == p.Engine && candidate.Target.ConfigSHA256 == p.ConfigSHA256 && candidate.Target.Policy == p.Policy &&
		p.Created.MatchesPrepared(candidate.Target.Native)
}

func sameAcceptedRequest(a, b *JournalIntent) bool {
	return a != nil && b != nil && a.RequestID == b.RequestID && a.ProfileID == b.ProfileID &&
		a.ProfileRevision == b.ProfileRevision && a.ResultProfileRevision == b.ResultProfileRevision
}

// A preparation can gain one receipt, promote that exact receipt into one
// successor intent, or roll back to its unchanged predecessor. The caller
// must prove the native candidate is absent and its engine joined before
// rollback; recording a rollback is never permission to discard an owner.
func checkPreparationTransition(previous, next JournalRecord) error {
	old := previous.Intent
	if next.Phase == "settled" {
		if !sameState(next.Committed, previous.Committed) {
			return errors.New("Linux preparation rollback changed its retained predecessor")
		}
		return nil
	}
	i := next.Intent
	if next.Phase != "intent" || !sameState(next.Committed, previous.Committed) || !sameAcceptedRequest(old, i) ||
		!samePreparation(old.Preparation, i.Preparation, false) {
		return errors.New("Linux preparation changed its original accepted request or captured owner")
	}
	switch i.Action {
	case "prepare":
		if old.Preparation.Created == nil && i.Preparation.Created != nil {
			return nil
		}
	case "successor":
		if old.Preparation.Created != nil && samePreparation(old.Preparation, i.Preparation, true) {
			return nil
		}
	}
	return errors.New("Linux preparation skipped or replayed its original native creation receipt")
}
