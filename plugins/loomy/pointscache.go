package main

import (
	"strings"
	"sync"
	"time"

	"github.com/collegeming/cpa-jethub-plugins/internal/abiboot"
)

// pointsCacheEntry remembers one balance read long enough that a status page
// reload or a quota.fetch burst inside the TTL costs zero upstream calls.
type pointsCacheEntry struct {
	// Snapshot is nil-and-cacheable: "the server did not publish balance" is
	// itself a fact for the TTL, not a reason to retry on every page load.
	Snapshot *pointsSnapshot
	Fetched  time.Time
}

var pointsCache sync.Map // account key -> pointsCacheEntry

// grantDays remembers, per account, the business day whose daily grant this
// plugin last saw initialised — claimed by this call or already processed.
//
// The records read rarely carries dailyCycleDate, and the pool sweep decides
// whether a claim is still due from that field alone: without this memory every
// sweep found every account unclaimed and re-posted first-login for all of
// them, every five minutes.
var grantDays sync.Map // account key -> "YYYY-MM-DD"

// pointsCacheKey identifies the account one snapshot belongs to. UserID is
// the stable account id; the phone number is the fallback for credentials
// that carry none (WeChat-bound accounts).
func pointsCacheKey(credential *Credential) string {
	if credential == nil {
		return ""
	}
	if id := strings.TrimSpace(credential.UserID); id != "" {
		return "u:" + id
	}
	if phone := strings.TrimSpace(credential.Phone); phone != "" {
		return "p:" + phone
	}
	return ""
}

// pointsFreshness says how old a remembered snapshot may be before a read goes
// upstream again.
type pointsFreshness int

const (
	// pointsWithinTTL reuses a snapshot younger than points_cache_ttl_ms. The
	// status document and quota.fetch use it: their readers act on the figures.
	pointsWithinTTL pointsFreshness = iota
	// pointsAnyAge reuses a snapshot of any age. The status page uses it and
	// prints the read time beside the figures, so a view costs no upstream call
	// once the pool sweep or an earlier view has read the account.
	pointsAnyAge
	// pointsLive always reads upstream: the status page's 刷新积分 action.
	pointsLive
)

// readPoints returns one account's snapshot and the time it was read.
//
// Read failures are never cached: a transient transport error must not stick
// to the account. points_cache_ttl_ms = 0 turns all reuse off, the any-age
// reuse of the status page included.
func readPoints(h *abiboot.Host, credential *Credential, cfg Config, freshness pointsFreshness) (*pointsSnapshot, time.Time, error) {
	ttl := time.Duration(cfg.PointsCacheTTLMS) * time.Millisecond
	key := pointsCacheKey(credential)
	if ttl <= 0 || key == "" {
		snapshot, err := fetchPoints(h, credential, cfg)
		return snapshot, time.Now(), err
	}
	if freshness != pointsLive {
		if value, ok := pointsCache.Load(key); ok {
			if entry, ok := value.(pointsCacheEntry); ok && (freshness == pointsAnyAge || time.Since(entry.Fetched) < ttl) {
				return entry.Snapshot, entry.Fetched, nil
			}
		}
	}
	snapshot, err := fetchPoints(h, credential, cfg)
	fetched := time.Now()
	if err == nil {
		pointsCache.Store(key, pointsCacheEntry{Snapshot: snapshot, Fetched: fetched})
	}
	return snapshot, fetched, err
}

// cachedFetchPoints wraps fetchPoints with the configured per-account TTL.
func cachedFetchPoints(h *abiboot.Host, credential *Credential, cfg Config) (*pointsSnapshot, error) {
	snapshot, _, err := readPoints(h, credential, cfg, pointsWithinTTL)
	return snapshot, err
}

// invalidatePoints drops one account's remembered balance so the read after a
// write (daily grant claim) shows the fresh figure.
func invalidatePoints(credential *Credential) {
	if key := pointsCacheKey(credential); key != "" {
		pointsCache.Delete(key)
	}
}

// rememberGrantDay records that the account's daily grant is initialised for
// day.
func rememberGrantDay(credential *Credential, day string) {
	day = strings.TrimSpace(day)
	if key := pointsCacheKey(credential); key != "" && day != "" {
		grantDays.Store(key, day)
	}
}

// grantDayOf returns the business day the account's daily grant was last seen
// initialised, or "" when this plugin has not seen it since it loaded.
func grantDayOf(credential *Credential) string {
	if key := pointsCacheKey(credential); key != "" {
		if value, ok := grantDays.Load(key); ok {
			day, _ := value.(string)
			return day
		}
	}
	return ""
}

// resetPointsCache clears every remembered balance and grant day; tests use it
// so a stubbed transport is not masked by an earlier test's reads.
func resetPointsCache() {
	for _, cache := range []*sync.Map{&pointsCache, &grantDays} {
		cache.Range(func(key, _ any) bool {
			cache.Delete(key)
			return true
		})
	}
}
