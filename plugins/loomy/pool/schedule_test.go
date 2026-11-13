package pool

import (
	"testing"
	"time"
)

func TestScheduledCheckinTimeIsStableAndInsideWindow(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CheckinWindowStart = "00:10"
	cfg.CheckinWindowEnd = "06:00"
	loc := BusinessLocation()
	day := time.Date(2026, 11, 13, 12, 0, 0, 0, loc)
	account := statusAccount{Name: "loomy-a.json", AuthIndex: "idx-a"}

	first := scheduledCheckinTime(account, day, cfg)
	second := scheduledCheckinTime(account, day.Add(3*time.Hour), cfg)
	if !first.Equal(second) {
		t.Fatalf("slot moved from %s to %s within the same day", first, second)
	}
	start := time.Date(2026, 11, 13, 0, 10, 0, 0, loc)
	end := time.Date(2026, 11, 13, 6, 0, 0, 0, loc)
	if first.Before(start) || !first.Before(end) {
		t.Fatalf("slot %s is outside 00:10–06:00", first)
	}

	other := scheduledCheckinTime(statusAccount{Name: "loomy-b.json", AuthIndex: "idx-b"}, day, cfg)
	if first.Equal(other) {
		t.Fatal("two accounts must not be assigned the exact same slot (very unlikely with a 6h window)")
	}

	nextDay := scheduledCheckinTime(account, day.Add(24*time.Hour), cfg)
	if first.Day() == nextDay.Day() && first.Equal(nextDay) {
		t.Fatal("the slot is allowed to change across days")
	}
	if nextDay.Format("2006-01-02") != "2026-11-14" {
		t.Fatalf("next-day slot = %s, want 14 Nov", nextDay)
	}
}

func TestCheckinDueAtWindowAndCatchUp(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CheckinWindowStart = "00:10"
	cfg.CheckinWindowEnd = "06:00"
	loc := BusinessLocation()
	account := statusAccount{
		Name: "loomy-a.json", AuthIndex: "idx-a",
		Points: &struct {
			Available      *float64 `json:"available"`
			Balance        *float64 `json:"balance"`
			DailyBalance   *float64 `json:"daily_balance"`
			DailyQuota     *float64 `json:"daily_quota"`
			DailyConsumed  *float64 `json:"daily_consumed"`
			DailyCycleDate string   `json:"daily_cycle_date"`
		}{DailyCycleDate: "2026-11-12"},
	}
	slot := scheduledCheckinTime(account, time.Date(2026, 11, 13, 12, 0, 0, 0, loc), cfg)

	preWindow := time.Date(2026, 11, 13, 0, 5, 0, 0, loc)
	if checkinDueAt(account, preWindow, cfg) {
		t.Fatal("00:05 is before the window and must not claim")
	}
	justBefore := slot.Add(-time.Second)
	if !justBefore.Before(slot) {
		t.Fatal("setup")
	}
	if checkinDueAt(account, justBefore, cfg) {
		t.Fatal("a second before the slot must not claim")
	}
	if !checkinDueAt(account, slot, cfg) {
		t.Fatal("the scheduled instant itself is due")
	}
	afterWindow := time.Date(2026, 11, 13, 15, 0, 0, 0, loc)
	if !checkinDueAt(account, afterWindow, cfg) {
		t.Fatal("after the window closes, a missed slot must still be claimed (catch-up)")
	}

	claimed := account
	claimed.Points.DailyCycleDate = "2026-11-13"
	if checkinDueAt(claimed, afterWindow, cfg) {
		t.Fatal("an already-claimed account must not be due again the same day")
	}
}

func TestWaitCheckinGapIsSerialAndBounded(t *testing.T) {
	var slept []time.Duration
	previous := checkinWait
	checkinWait = func(d time.Duration) { slept = append(slept, d) }
	t.Cleanup(func() { checkinWait = previous })

	cfg := DefaultConfig()
	cfg.CheckinGapMinMS = 2000
	cfg.CheckinGapMaxMS = 15000
	for i := 0; i < 20; i++ {
		waitCheckinGap(cfg)
	}
	if len(slept) != 20 {
		t.Fatalf("slept %d times, want 20", len(slept))
	}
	for _, d := range slept {
		if d < 2*time.Second || d > 15*time.Second {
			t.Fatalf("gap %s outside 2–15s", d)
		}
	}
	// Zero max disables the wait.
	slept = nil
	cfg.CheckinGapMaxMS = 0
	waitCheckinGap(cfg)
	if len(slept) != 0 {
		t.Fatalf("gap with max=0 still slept: %v", slept)
	}
}
