package main

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

// Risk circuit breaker, following Loomy2api-CPAMC `plugin/guard.go`.
//
// When two or more different accounts are rejected by upstream risk control
// (HTTP 403, TM.* codes, or a body that talks about 风控 / 异常行为) inside a
// 10-minute window, every subsequent request is held locally for
// RiskPauseSec (default 1800s) so the whole pool is not dragged into the
// same ban wave. A 403 never triggers a password re-login.
//
// 100003 (account disabled by the platform) is a different signal and is
// handled in envelope.go; it is not a risk-control hit and does not trip
// this breaker.

const (
	defaultRiskPauseSec = 1800
	riskWindow          = 10 * time.Minute
	riskAccounts        = 2
)

var (
	riskMu      sync.Mutex
	riskHits    = map[string]time.Time{}
	pausedUntil time.Time
	pauseReason string
)

// isRiskRejection reports upstream answers that look like risk control rather
// than an expired session. Loomy signals expiry as HTTP 200 + code 100002;
// risk control is typically HTTP 403 or a TM.* body.
func isRiskRejection(status int, code, body string) bool {
	if status == http.StatusForbidden {
		return true
	}
	if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(code)), "TM.") {
		return true
	}
	return strings.Contains(body, "TM.0000") ||
		strings.Contains(body, "风控") ||
		strings.Contains(body, "异常行为")
}

// noteRisk records a rejection against a masked account identity and trips
// the breaker when enough distinct accounts were hit inside the window.
func noteRisk(account, detail string) {
	if account == "" {
		account = "unknown"
	}
	now := time.Now()
	riskMu.Lock()
	riskHits[account] = now
	n := 0
	for acc, t := range riskHits {
		if now.Sub(t) > riskWindow {
			delete(riskHits, acc)
			continue
		}
		n++
	}
	riskMu.Unlock()

	sec := settings().riskPauseSeconds()
	if sec <= 0 || n < riskAccounts {
		return
	}
	until := now.Add(time.Duration(sec) * time.Second)
	riskMu.Lock()
	if !pausedUntil.IsZero() && pausedUntil.After(until.Add(-60*time.Second)) {
		riskMu.Unlock()
		return
	}
	pausedUntil = until
	pauseReason = "多个账号在短时间内被风控拒绝"
	riskMu.Unlock()
}

// pauseRemaining returns how long the breaker still holds requests.
func pauseRemaining() time.Duration {
	riskMu.Lock()
	defer riskMu.Unlock()
	if pausedUntil.IsZero() {
		return 0
	}
	left := time.Until(pausedUntil)
	if left <= 0 {
		pausedUntil = time.Time{}
		pauseReason = ""
		return 0
	}
	return left
}

// riskPausedError is returned from the executor when the breaker is open,
// so the host can try a later request (or a different account) without
// sending more traffic upstream and without treating it as a dead session.
func riskPausedError() error {
	left := pauseRemaining()
	if left <= 0 {
		return nil
	}
	retry := int(left.Seconds())
	if retry < 1 {
		retry = 1
	}
	return statusError(true, "risk_breaker", http.StatusTooManyRequests,
		"Loomy 风控熔断中，%d 秒后重试（%s）", retry, pauseReason)
}

// riskControlError classifies an upstream 403 (or TM.* body) as a
// non-credential failure: it must not trigger a re-login.
func riskControlError(status int, detail string) error {
	return statusError(false, "risk_control", http.StatusForbidden,
		"Loomy 风控拒绝（HTTP %d）：%s", status, detail)
}

// releaseRiskPause lifts the breaker. Intended for tests and a future
// management action; production expiry is time-based.
func releaseRiskPause() {
	riskMu.Lock()
	pausedUntil = time.Time{}
	pauseReason = ""
	riskHits = map[string]time.Time{}
	riskMu.Unlock()
}

func resetRiskBreaker() { releaseRiskPause() }

// riskState is a diagnostic snapshot that never includes account identifiers
// beyond a count.
func riskState() map[string]any {
	left := pauseRemaining()
	riskMu.Lock()
	recent := 0
	now := time.Now()
	for _, t := range riskHits {
		if now.Sub(t) <= riskWindow {
			recent++
		}
	}
	reason := pauseReason
	riskMu.Unlock()
	st := map[string]any{
		"risk_pause_sec": settings().riskPauseSeconds(),
		"paused":         left > 0,
		"paused_left":    int(left.Seconds()),
		"pause_reason":   reason,
		"recent_risk":    recent,
	}
	return st
}
