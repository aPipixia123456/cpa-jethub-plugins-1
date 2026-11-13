package pool

import (
	"crypto/sha256"
	"encoding/binary"
	"math/rand"
	"strings"
	"time"
)

// Randomized daily check-in.
//
// Each account is assigned a time inside the configured window (default
// 00:10–06:00 Asia/Shanghai). The instant is stable for a given account on a
// given business day (hash of identity + date), so a 5-minute sweep does not
// bunch every account at the first tick after midnight. Accounts whose slot
// has already passed (including after the window ends) are still claimed so
// a missed slot does not skip the whole day.
//
// When several accounts become due in the same sweep they are processed
// serially, with a random gap between them (production only: the sleep hook
// is armed when the background scanner starts, so unit tests stay instant).

const (
	DefaultCheckinWindowStart = "00:10"
	DefaultCheckinWindowEnd   = "06:00"
	DefaultCheckinTimezone    = "Asia/Shanghai"
	DefaultCheckinGapMinMS    = 2000
	DefaultCheckinGapMaxMS    = 15000
)

// shanghai is Loomy's business zone. Loaded once; falls back to a fixed
// UTC+8 offset if the tzdata is missing.
var shanghai = func() *time.Location {
	loc, err := time.LoadLocation(DefaultCheckinTimezone)
	if err != nil {
		return time.FixedZone("CST", 8*60*60)
	}
	return loc
}()

// checkinWait is the sleep used between serial claims. The zero value is a
// no-op so unit tests that call runScan remain instant. startScanner arms
// it with time.Sleep.
var checkinWait = func(time.Duration) {}

func enableCheckinGaps()  { checkinWait = time.Sleep }
func disableCheckinGaps() { checkinWait = func(time.Duration) {} }

// BusinessLocation is the zone used for the daily window and BusinessDay.
func BusinessLocation() *time.Location { return shanghai }

// parseClock parses "HH:MM" or "HH:MM:SS" into a duration from midnight.
func parseClock(text, fallback string) time.Duration {
	for _, candidate := range []string{strings.TrimSpace(text), fallback} {
		for _, layout := range []string{"15:04:05", "15:04"} {
			if parsed, err := time.Parse(layout, candidate); err == nil {
				return time.Duration(parsed.Hour())*time.Hour +
					time.Duration(parsed.Minute())*time.Minute +
					time.Duration(parsed.Second())*time.Second
			}
		}
	}
	return 10 * time.Minute
}

func windowBounds(cfg Config) (start, end time.Duration) {
	start = parseClock(cfg.CheckinWindowStart, DefaultCheckinWindowStart)
	end = parseClock(cfg.CheckinWindowEnd, DefaultCheckinWindowEnd)
	if end <= start {
		end = start + time.Hour
	}
	return start, end
}

// checkinSeed is the stable identity used to place an account in the window.
func checkinSeed(account statusAccount) string {
	for _, candidate := range []string{account.AuthIndex, account.Name, account.Label} {
		if strings.TrimSpace(candidate) != "" {
			return strings.TrimSpace(candidate)
		}
	}
	return "loomy-account"
}

// scheduledCheckinTime is the instant this account should be claimed on the
// business day of `now`. It is deterministic for (identity, day).
func scheduledCheckinTime(account statusAccount, now time.Time, cfg Config) time.Time {
	loc := shanghai
	local := now.In(loc)
	day := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, loc)
	start, end := windowBounds(cfg)
	span := end - start
	if span <= 0 {
		return day.Add(start)
	}
	sum := sha256.Sum256([]byte("loomy-checkin:" + checkinSeed(account) + ":" + day.Format("2006-01-02")))
	offset := binary.BigEndian.Uint64(sum[:8]) % uint64(span)
	return day.Add(start + time.Duration(offset))
}

// dayNeedsCheckin reports whether the account has not already claimed today's
// daily grant, based on the daily_cycle_date the provider reports.
func dayNeedsCheckin(account statusAccount, now time.Time) bool {
	if account.Points == nil {
		return true
	}
	cycle := strings.TrimSpace(account.Points.DailyCycleDate)
	today := now.In(shanghai).Format("2006-01-02")
	return cycle == "" || cycle < today
}

// checkinDueAt reports whether this account should be claimed at `now`: the
// grant is not yet taken for the business day, and the scheduled slot has
// arrived (or the window has already closed — catch-up).
func checkinDueAt(account statusAccount, now time.Time, cfg Config) bool {
	if !dayNeedsCheckin(account, now) {
		return false
	}
	return !now.In(shanghai).Before(scheduledCheckinTime(account, now, cfg))
}

// waitCheckinGap sleeps a random duration between the configured bounds.
func waitCheckinGap(cfg Config) {
	minMS := cfg.CheckinGapMinMS
	maxMS := cfg.CheckinGapMaxMS
	if maxMS <= 0 {
		return
	}
	if minMS < 0 {
		minMS = 0
	}
	if maxMS < minMS {
		maxMS = minMS
	}
	span := maxMS - minMS
	delay := minMS
	if span > 0 {
		delay += rand.Intn(span + 1)
	}
	if delay <= 0 {
		return
	}
	checkinWait(time.Duration(delay) * time.Millisecond)
}
