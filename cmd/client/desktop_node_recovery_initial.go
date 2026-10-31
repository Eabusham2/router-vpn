package main

import (
	"context"
	"errors"
)

// Only the native retained startup store can prove initial namespace absence.
// An os.ErrNotExist, empty snapshot, nil store or missing header/peer is never
// this witness. Ordinary journal stores continue through exact recovery.
type desktopNodeInitialJournalAbsence interface {
	InitialAbsence(context.Context) (bool, error)
}

// Called with the slot lock held. A failed absence-owner close is retried on
// that owner, then the namespace is reopened and independently proved again.
// Old absence cannot authorize a later foreign or incomplete journal.
func (s *desktopNodeProtectionSlot) openRecoveryJournalLocked(ctx context.Context, check func() error, requireJournal bool) (bool, error) {
	r := s.recovery
	if r == nil || r.backend.open == nil || check == nil {
		return false, errors.New("startup journal has no captured native opener")
	}
	if r.absenceClosing {
		if s.journal == nil {
			return false, errors.New("startup absence lost its retained close owner")
		}
		if err := s.journal.Close(); err != nil {
			return false, err
		}
		s.journal, r.opened, r.absenceClosing = nil, false, false
	}
	if !r.opened {
		if s.journal != nil {
			if err := s.journal.Close(); err != nil {
				return false, err
			}
			s.journal = nil
		}
		if err := check(); err != nil {
			return false, err
		}
		store, err := r.backend.open(ctx)
		if store != nil {
			s.journal = store // partial native files/lock remain owned on failure
		}
		if err != nil || store == nil {
			return false, errors.Join(err, errors.New("startup recovery could not retain its original private journal"))
		}
		r.opened = true
	}
	absence, capable := s.journal.(desktopNodeInitialJournalAbsence)
	if !capable {
		return false, nil
	}
	absent, err := absence.InitialAbsence(ctx)
	if err != nil {
		return false, err
	}
	if !absent {
		return false, nil
	}
	if r.head != nil || r.owner != nil || r.result != nil || r.proved || s.known || s.target != nil || s.active != nil || s.off != nil {
		return false, errors.New("startup absence cannot erase a recorded or active protection owner")
	}
	if err := check(); err != nil {
		return false, err
	}
	r.absenceClosing = true
	if err := s.journal.Close(); err != nil {
		return false, err
	}
	s.journal, r.opened, r.absenceClosing = nil, false, false
	if err := check(); err != nil {
		return false, err
	}
	// Creation belongs to this source-start call. A cancelled earlier start
	// cannot confer creation authority on a later read-only recovery request.
	if !requireJournal {
		return true, nil
	}
	if r.backend.create == nil {
		return false, errors.New("native source start has no captured journal creator")
	}
	// Create independently reproves actual BFE/namespace absence. A concurrent
	// creator or incomplete peer causes failure; no old bytes are overwritten.
	store, err := r.backend.create(ctx)
	if store != nil {
		s.journal = store
	}
	if err != nil || store == nil {
		return false, errors.Join(err, errors.New("native source start could not retain its durable journal"))
	}
	r.opened = true
	return false, check()
}
