package main

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

// deviceIDSalt is a local, non-secret namespace so a phone number does not
// hash to the same UUID a different plugin would produce.
const deviceIDSalt = "loomy-cpa-device:"

// deviceIDFor returns a stable UUID derived from a phone number (or another
// per-account seed). The official desktop client sends a device id; a pool
// that reused a single "web" value would look like one device with many
// sessions. The hash is deterministic: the same phone always produces the
// same id, across process restarts.
func deviceIDFor(seed string) string {
	trimmed := strings.TrimSpace(seed)
	if trimmed == "" {
		return ""
	}
	// Prefer the normalised 11-digit form when the seed is a phone number, so
	// "13800138000" and "+86 138 0013 8000" share one device id.
	if phone := normalizePhone(trimmed); validPhone(phone) {
		trimmed = phone
	}
	sum := sha256.Sum256([]byte(deviceIDSalt + trimmed))
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// deviceIDForCredential prefers the bound phone, then the user id, then a
// session-derived seed, so a WeChat bind/skip credential still gets a stable
// id even with an empty phone.
func deviceIDForCredential(credential *Credential) string {
	if credential == nil {
		return ""
	}
	if id := deviceIDFor(credential.Phone); id != "" {
		return id
	}
	if id := deviceIDFor(credential.UserID); id != "" {
		return id
	}
	return deviceIDFor(credential.Session())
}
