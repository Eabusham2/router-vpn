//go:build linux

package desktopnetwork

import (
	"context"
	"errors"
	"os"
	"runtime"
	"sort"
	"syscall"
)

// ResolvedNamespace binds numeric link indexes to the original observer's
// kernel namespace. The namespace descriptor was opened on the same locked OS
// thread as its subscribed Netlink socket. A saved dev/inode pair alone never
// establishes this provenance.
func (t *Tracker) ResolvedNamespace(ctx context.Context) (uint64, uint64, []int32, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if t == nil {
		return 0, 0, nil, errors.New("resolved policy lost physical observer")
	}
	if err := t.CurrentContext(ctx); err != nil {
		return 0, 0, nil, err
	}
	if err := LockContext(ctx, &t.mu); err != nil {
		return 0, 0, nil, err
	}
	defer t.mu.Unlock()
	o, ok := t.native.(*linuxObserver)
	if !ok || t.closed || t.closing || t.transition || t.failureError() != nil {
		return 0, 0, nil, errors.New("resolved policy requires original Linux physical observer")
	}
	if err := LockContext(ctx, &o.mu); err != nil {
		return 0, 0, nil, err
	}
	defer o.mu.Unlock()
	device, inode, err := o.resolvedNamespaceCurrent()
	if err != nil {
		return 0, 0, nil, err
	}
	indexes := make([]int32, 0, len(t.physical.Links))
	for _, link := range t.physical.Links {
		if link.Index == 0 || link.Index > 1<<31-1 {
			return 0, 0, nil, errors.New("resolved policy link index outside native range")
		}
		indexes = append(indexes, int32(link.Index))
	}
	sort.Slice(indexes, func(i, j int) bool { return indexes[i] < indexes[j] })
	return device, inode, indexes, ctx.Err()
}

func (o *linuxObserver) resolvedNamespaceCurrent() (uint64, uint64, error) {
	if o.closed || o.closing || o.namespace == nil || o.namespace != o.originalNamespace || o.namespaceInfo == nil {
		return 0, 0, errors.New("resolved policy lost original observer namespace")
	}
	info, err := o.namespace.Stat()
	current, other := os.Stat("/proc/thread-self/ns/net")
	if err != nil || other != nil || !os.SameFile(info, o.namespaceInfo) || !os.SameFile(current, o.namespaceInfo) {
		return 0, 0, errors.New("resolved policy changed original observer namespace")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Ino == 0 {
		return 0, 0, errors.New("resolved policy has no kernel namespace identity")
	}

	return uint64(stat.Dev), stat.Ino, nil
}
