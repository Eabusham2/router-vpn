package main

import (
	"errors"
	"sync"
)

// Temporary Speed Lab configurations are deliberately non-persistent. The
// connection transaction still uses the real runtime/proof paths, but ranking
// hints and last-good startup memory must not serialize the temporary node,
// base, AUTO filters, mode, or graph if the process dies before normal cleanup.
// operationMu already serializes one connection/settings owner; this guard is a
// second explicit invariant consumed by background/durable writers.
var speedLabTemporaryPersistenceOwners sync.Map // map[*app]struct{}

func beginSpeedLabTemporaryPersistenceGuard(a *app) (func(), error) {
	if a == nil {
		return nil, errors.New("Speed Lab temporary persistence guard requires an app owner")
	}
	if _, loaded := speedLabTemporaryPersistenceOwners.LoadOrStore(a, struct{}{}); loaded {
		return nil, errors.New("another temporary Speed Lab persistence guard is already active")
	}
	return func() { speedLabTemporaryPersistenceOwners.Delete(a) }, nil
}

func speedLabTemporaryPersistenceSuppressed(a *app) bool {
	if a == nil {
		return false
	}
	_, ok := speedLabTemporaryPersistenceOwners.Load(a)
	return ok
}
