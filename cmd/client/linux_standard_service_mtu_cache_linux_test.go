//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/mobilemtu"
)

func standardMTUCacheFixture(t *testing.T) *linuxStandardMTUCache {
	t.Helper()
	cache, err := openLinuxStandardMTUCache(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return cache
}
func TestLinuxStandardMTUCacheOriginalPathTTLAndBound(t *testing.T) {
	cache := standardMTUCacheFixture(t)
	ctx := context.Background()
	valid := func(ctx context.Context) error { return ctx.Err() }
	for i := 0; i < 65; i++ {
		key := strings.Repeat("0", 62) + "0123456789abcdef"[i/16:i/16+1] + "0123456789abcdef"[i%16:i%16+1]
		if err := cache.SaveContext(ctx, key, 1280+i, valid); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := readPrivateRegular(cache.path, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Version int                         `json:"version"`
		Entries map[string]mobilemtu.Record `json:"entries"`
	}
	if json.Unmarshal(raw, &document) != nil || document.Version != 3 || len(document.Entries) != 64 {
		t.Fatal("cache lost bounded shared schema")
	}
	key := strings.Repeat("f", 64)
	for _, test := range []struct {
		name   string
		tested int64
		want   bool
	}{{"fresh", time.Now().Unix(), true}, {"expired", time.Now().Add(-25 * time.Hour).Unix(), false}, {"future", time.Now().Add(time.Hour).Unix(), false}} {
		t.Run(test.name, func(t *testing.T) {
			document.Entries = map[string]mobilemtu.Record{key: {MTU: 1380, Tested: test.tested}}
			body, _ := json.Marshal(document)
			if err := atomicWritePrivate(cache.path, body); err != nil {
				t.Fatal(err)
			}
			mtu, found, err := cache.LookupContext(ctx, key)
			if err != nil || found != test.want || found && mtu != 1380 {
				t.Fatal(mtu, found, err)
			}
			if _, foreign, _ := cache.LookupContext(ctx, strings.Repeat("e", 64)); foreign {
				t.Fatal("another captured path borrowed history")
			}
		})
	}
}
func TestLinuxStandardMTUCacheCanceledSaveRollsBackOnlyOwnBytes(t *testing.T) {
	for _, newer := range []bool{false, true} {
		t.Run(map[bool]string{false: "restore-original", true: "retain-newer"}[newer], func(t *testing.T) {
			cache := standardMTUCacheFixture(t)
			base, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx, finish, err := mobilemtu.WithOperationContext(base, time.Second, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer finish()
			prior := `{"version":3,"entries":{}}`
			if err := atomicWritePrivate(cache.path, []byte(prior)); err != nil {
				t.Fatal(err)
			}
			foreign := `{"version":3,"entries":{"` + strings.Repeat("b", 64) + `":{"mtu":1400,"tested_at":1}}}`
			calls := 0
			err = cache.SaveContext(ctx, strings.Repeat("a", 64), 1380, func(ctx context.Context) error {
				calls++
				if calls == 4 {
					if newer {
						if err := atomicWritePrivate(cache.path, []byte(foreign)); err != nil {
							t.Fatal(err)
						}
					}
					cancel()
				}
				return ctx.Err()
			})
			if !errors.Is(err, context.Canceled) || calls != 4 {
				t.Fatal("late save lost cancellation", err, calls)
			}
			raw, err := readPrivateRegular(cache.path, 64<<10)
			if err != nil {
				t.Fatal(err)
			}
			want := prior
			if newer {
				want = foreign
			}
			if string(raw) != want {
				t.Fatal("stale cache save overwrote another owner's bytes", string(raw))
			}
		})
	}
}
func TestLinuxStandardMTUCacheDeadlineAndDirectoryReplacement(t *testing.T) {
	cache := standardMTUCacheFixture(t)
	cache.mu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, _, err := cache.LookupContext(ctx, strings.Repeat("a", 64))
	cache.mu.Unlock()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	root := filepath.Dir(cache.path)
	if err := os.Rename(root, root+"-original"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root + "-original") })
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := cache.SaveContext(context.Background(), strings.Repeat("a", 64), 1380, func(context.Context) error { return nil }); err == nil {
		t.Fatal("replaced cache directory adopted measured history")
	}
	if _, err := os.Stat(cache.path); !os.IsNotExist(err) {
		t.Fatal("replacement cache was touched", err)
	}
}
