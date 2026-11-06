//go:build linux

package main

import (
	"context"
	"errors"
	"router-vpn/internal/common"
	"router-vpn/internal/mobiletor"
	"router-vpn/internal/systembootstrap"
	"sync"
	"time"
)

type resolvedGroupRetirementError struct{ err error }

func (e *resolvedGroupRetirementError) Error() string { return e.err.Error() }
func (e *resolvedGroupRetirementError) Unwrap() error { return e.err }

type resolvedQueryScope struct {
	mobiletor.DesktopLinuxBootstrapDNSUpstream
	opportunistic *mobiletor.DesktopLinuxOpportunisticDNS
	current       func(context.Context) error
	validate      func(context.Context) ([]byte, error)
}
type resolvedOpportunisticQueryGroup interface {
	ExchangeOpportunistic(context.Context, *mobiletor.DesktopLinuxOpportunisticDNS, []byte, func(context.Context) error) ([]byte, error)
}

type resolvedQueryGroup interface {
	Exchange(context.Context, mobiletor.DesktopLinuxBootstrapDNSUpstream, []byte) ([]byte, error)
	Close(context.Context) error
}

// resolveOriginalScopes starts every equally preferred original scope. Only a
// fully validated positive answer cancels siblings; a negative answer remains
// provisional until every other scope has completed. The group must release
// and join its original sockets/grants before any answer can be adopted.
func resolveOriginalScopes(ctx context.Context, group resolvedQueryGroup, upstreams []resolvedQueryScope, question []byte) ([]byte, error) {
	return resolveOriginalScopesOwned(ctx, group, upstreams, question, nil)
}
func resolveOriginalScopesOwned(ctx context.Context, group resolvedQueryGroup, upstreams []resolvedQueryScope, question []byte, retire func(context.Context) error) ([]byte, error) {
	query, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		index    int
		answer   []byte
		positive bool
		err      error
	}
	results := make(chan result, len(upstreams))
	var workers sync.WaitGroup
	for i, upstream := range upstreams {
		workers.Add(1)
		go func(index int, server resolvedQueryScope) {
			defer workers.Done()
			var answer []byte
			var err error
			if server.validate != nil {
				answer, err = server.validate(query)
			} else if server.opportunistic != nil {
				transport, ok := group.(resolvedOpportunisticQueryGroup)
				if !ok {
					err = errors.New("original group omitted captured opportunistic transport")
				} else {
					answer, err = transport.ExchangeOpportunistic(query, server.opportunistic, question, server.current)
				}
			} else {
				answer, err = group.Exchange(query, server.DesktopLinuxBootstrapDNSUpstream, question)
			}
			if err == nil && server.validate == nil && server.opportunistic == nil && server.Network == "udp" && common.ValidateDNSForwardResponse(question, answer) == nil && answer[2]&2 != 0 {
				server.Network = "tcp"
				answer, err = group.Exchange(query, server.DesktopLinuxBootstrapDNSUpstream, question)
			}
			positive := false
			if err == nil {
				positive, err = systembootstrap.ResolvedResponseSuccess(question, answer)
			}
			results <- result{index, answer, positive, err}
		}(i, upstream)
	}
	var winner []byte
	negatives := make([][]byte, len(upstreams))
	var failures error
	remaining := len(upstreams)
collect:
	for remaining > 0 {
		select {
		case <-ctx.Done():
			failures = errors.Join(failures, ctx.Err())
			break collect
		case r := <-results:
			remaining--
			if r.err != nil {
				failures = errors.Join(failures, r.err)
				continue
			}
			if r.positive {
				winner = r.answer
				break collect
			}
			negatives[r.index] = r.answer
		}
	}
	cancel()
	// This clock permits retirement only. It cannot admit another query or
	// replace the immutable original deadline held by the group.
	cleanup, finish := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer finish()
	joined := make(chan struct{})
	go func() { workers.Wait(); close(joined) }()
	if retire != nil {
		select {
		case <-joined:
		case <-cleanup.Done():
			return nil, &resolvedGroupRetirementError{cleanup.Err()}
		}
		if err := retire(cleanup); err != nil {
			return nil, &resolvedGroupRetirementError{errors.Join(failures, err)}
		}
	}
	if err := group.Close(cleanup); err != nil {
		return nil, &resolvedGroupRetirementError{errors.Join(failures, err)}
	}
	select {
	case <-joined:
	case <-cleanup.Done():
		return nil, cleanup.Err()
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if winner != nil {
		return winner, nil
	}
	for _, answer := range negatives {
		if answer != nil {
			return answer, nil
		}
	}
	if failures == nil {
		failures = errors.New("original resolved scopes produced no answer")
	}
	return nil, failures
}
