package mobilemtu

import (
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"time"
)

// Preferences belongs to the VPN application's existing private store. CAS
// prevents stale completion or rollback from replacing a newer saved record.
type Preferences interface {
	ReadMTUCache() (string, error)
	CompareAndSwapMTUCache(string, string) (bool, error)
}
type Record struct {
	MTU    int   `json:"mtu"`
	Tested int64 `json:"tested_at"`
}
type cacheDocument struct {
	Version int               `json:"version"`
	Entries map[string]Record `json:"entries"`
}
type PreferenceCache struct {
	mu    sync.Mutex
	store Preferences
}

func NewCache(store Preferences) *PreferenceCache { return &PreferenceCache{store: store} }
func (c *PreferenceCache) read() (string, cacheDocument, error) {
	empty := cacheDocument{Version: 3, Entries: map[string]Record{}}
	if c.store == nil {
		return "", empty, errors.New("private MTU cache is unavailable")
	}
	raw, err := c.store.ReadMTUCache()
	if err != nil {
		return "", empty, err
	}
	if raw == "" {
		return "", empty, nil
	}
	var data cacheDocument
	if strictJSON(raw, &data, 64*1024) != nil || data.Version != 3 || data.Entries == nil || len(data.Entries) > 64 {
		return raw, empty, errors.New("invalid bounded MTU cache")
	}
	for key, value := range data.Entries {
		if !proofPattern.MatchString(key) || value.MTU < MinMTU || value.MTU > MaxMTU {
			return raw, empty, errors.New("invalid MTU cache record")
		}
	}
	return raw, data, nil
}
func (c *PreferenceCache) Lookup(key string) (int, bool) {
	if !proofPattern.MatchString(key) {
		return 0, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_, data, err := c.read()
	if err != nil {
		return 0, false
	}
	value, ok := data.Entries[key]
	now := time.Now().Unix()
	return value.MTU, ok && value.Tested >= now-24*3600 && value.Tested <= now+2
}
func (c *PreferenceCache) Save(key string, mtu int, valid func() bool) error {
	if !proofPattern.MatchString(key) || mtu < MinMTU || mtu > MaxMTU || valid == nil {
		return errors.New("invalid freshly measured MTU cache value")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !valid() {
		return errors.New("MTU result expired before persistence")
	}
	before, data, err := c.read()
	if err != nil {
		return err
	}
	data.Entries[key] = Record{MTU: mtu, Tested: time.Now().Unix()}
	if len(data.Entries) > 64 {
		keys := make([]string, 0, len(data.Entries))
		for key := range data.Entries {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool {
			a, b := data.Entries[keys[i]], data.Entries[keys[j]]
			if a.Tested == b.Tested {
				return keys[i] < keys[j]
			}
			return a.Tested < b.Tested
		})
		for _, old := range keys {
			if old != key {
				delete(data.Entries, old)
				break
			}
		}
	}
	encoded, err := json.Marshal(data)
	if err != nil || len(encoded) > 64*1024 {
		return errors.New("MTU cache exceeded its bound")
	}
	if !valid() {
		return errors.New("MTU result changed before private write")
	}
	changed, err := c.store.CompareAndSwapMTUCache(before, string(encoded))
	if err != nil || !changed {
		return errors.New("MTU preference write failed or another owner wrote first")
	}
	if !valid() {
		restored, restoreErr := c.store.CompareAndSwapMTUCache(string(encoded), before)
		if restoreErr != nil {
			return errors.New("stale MTU preference rollback failed")
		}
		if !restored {
			return errors.New("newer MTU preferences retained instead of overwriting them during rollback")
		}
		return errors.New("MTU result became stale during persistence and was rolled back")
	}
	return nil
}
