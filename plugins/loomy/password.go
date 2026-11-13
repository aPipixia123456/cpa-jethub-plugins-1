package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/collegeming/cpa-jethub-plugins/internal/abiboot"
)

// Password login against the iFlytek account host, following Loomy2api-CPAMC
// (`plugin/upstream.go` loginByPassword / rsaEncryptPassword).
//
// ── Set-password API finding ──
//
// Loomy's upstream does NOT expose an API that sets, changes or resets a
// password. Evidence, all read-only:
//
//   - Loomy2api-CPAMC (commit 48829e9, 2026-11-11) only calls
//     `/login/account/getPuKey` and `/login/account/byPwd`. Its SMS path
//     (`/login/phone/checkCode`) never sends a password, and SMS re-login
//     keeps a previously stored password only so auto-renew can keep working.
//     Adding an account requires the operator to supply a password the
//     account ALREADY has (`POST /loomy/add`).
//   - The same two endpoints are the only password-related account paths in
//     that repository; there is no setPwd / changePassword / resetPwd /
//     register-with-password call.
//   - The task quoted the older cpa-loomy-plugin comment that "上游没有设密码接口";
//     nothing in public Loomy2api-CPAMC source contradicts it.
//
// What this plugin can do: accept a user-supplied password during SMS /
// auto-SMS login (and via the password-login form), encrypt it into the
// local credential, and use it for `/login/account/byPwd` and scheduled
// auto-renew. A newly received SMS number that has never had a password set
// in the official Loomy client cannot be given one through this plugin.

const (
	// GetPuKeyPath returns the RSA public key and rcode used to encrypt a
	// password (`Loomy2api-CPAMC` loginByPassword).
	GetPuKeyPath = "/login/account/getPuKey"
	// ByPwdPath exchanges a phone number and an RSA-encrypted password for a
	// session (`Loomy2api-CPAMC` /login/account/byPwd).
	ByPwdPath = "/login/account/byPwd"

	// renewWindowDays is how many days of remaining session life trigger a
	// password re-login (`handleAuthRefresh` in Loomy2api-CPAMC).
	renewWindowDays = 4.0
)

// byPwdParam is the `param` of `/login/account/byPwd`.
type byPwdParam struct {
	LoginID  string `json:"loginid"`
	Password string `json:"password"`
	RCode    string `json:"rcode"`
	Type     int    `json:"type"`
	Expire   int    `json:"expire"`
}

// puKeyData is the usable part of a getPuKey answer.
type puKeyData struct {
	PuKey string `json:"pukey"`
	RCode string `json:"rcode"`
}

// loginByPassword signs in with a phone number and a plaintext password.
// The password is RSA-encrypted with the server's getPuKey material before it
// is sent; it is never written to a log or a request header.
func loginByPassword(h *abiboot.Host, cfg Config, phone, password string, now time.Time) (session, userID string, err error) {
	normalized := normalizePhone(phone)
	if !validPhone(normalized) {
		return "", "", statusError(false, "invalid_phone", http.StatusBadRequest,
			"手机号格式不正确（需要 11 位大陆手机号）")
	}
	if strings.TrimSpace(password) == "" {
		return "", "", statusError(false, "missing_password", http.StatusBadRequest, "请填写密码")
	}
	identity := accountIdentity{UA: cfg.clientUA(), DeviceID: deviceIDFor(normalized)}
	parsedKey, errKey := accountCallIdent(h, cfg, GetPuKeyPath, map[string]any{}, now, identity)
	if errKey != nil {
		return "", "", errKey
	}
	var key puKeyData
	if errDecode := parsedKey.decodeData(&key); errDecode != nil {
		return "", "", errDecode
	}
	if strings.TrimSpace(key.PuKey) == "" {
		return "", "", transportError("missing_pukey", "账号服务未返回公钥，无法密码登录")
	}
	encrypted, errEnc := rsaEncryptPassword(key.PuKey, password)
	if errEnc != nil {
		return "", "", transportError("encrypt_password", "加密密码失败：%v", errEnc)
	}
	parsed, errCall := accountCallIdent(h, cfg, ByPwdPath, byPwdParam{
		LoginID:  normalized,
		Password: encrypted,
		RCode:    key.RCode,
		Type:     1,
		Expire:   cfg.sessionTTL(),
	}, now, identity)
	if errCall != nil {
		return "", "", errCall
	}
	var data struct {
		Session string `json:"session"`
		UserID  string `json:"userid"`
	}
	if errDecode := parsed.decodeData(&data); errDecode != nil {
		return "", "", errDecode
	}
	if strings.TrimSpace(data.Session) == "" {
		return "", "", transportError("missing_session", "密码登录响应缺少 session")
	}
	return strings.TrimSpace(data.Session), strings.TrimSpace(data.UserID), nil
}

// rsaEncryptPassword encrypts a password with the account host's PKCS1/PKIX
// public key, matching Loomy2api-CPAMC.
func rsaEncryptPassword(pukeyB64, password string) (string, error) {
	der, errDecode := base64.StdEncoding.DecodeString(strings.TrimSpace(pukeyB64))
	if errDecode != nil {
		return "", errDecode
	}
	var pub *rsa.PublicKey
	if parsed, errPKIX := x509.ParsePKIXPublicKey(der); errPKIX == nil {
		if rp, ok := parsed.(*rsa.PublicKey); ok {
			pub = rp
		}
	}
	if pub == nil {
		if rp, errPKCS1 := x509.ParsePKCS1PublicKey(der); errPKCS1 == nil {
			pub = rp
		}
	}
	if pub == nil {
		return "", transportError("bad_pukey", "不支持的账号服务公钥格式")
	}
	enc, errEnc := rsa.EncryptPKCS1v15(rand.Reader, pub, []byte(password))
	if errEnc != nil {
		return "", errEnc
	}
	return base64.StdEncoding.EncodeToString(enc), nil
}

// sessionDaysLeft is the remaining lifetime in days, from the locally computed
// expires_at. ok is false when the expiry is unknown.
func sessionDaysLeft(credential *Credential, now time.Time) (float64, bool) {
	if credential == nil {
		return -1, false
	}
	expiry := credential.Expiry()
	if expiry.IsZero() {
		return -1, false
	}
	return expiry.Sub(now).Hours() / 24, true
}

// shouldRenewByPassword reports whether a password-backed credential should
// be re-logged-in: the probe failed, fewer than 4 days remain, or there is
// no local expiry to count down.
func shouldRenewByPassword(credential *Credential, alive bool, now time.Time) bool {
	if credential == nil || !credential.HasPassword() || !validPhone(credential.Phone) {
		return false
	}
	if !alive {
		return true
	}
	days, known := sessionDaysLeft(credential, now)
	if !known {
		return true
	}
	return days >= 0 && days < renewWindowDays
}

// renewBackoff returns the Loomy2api-CPAMC failure backoff:
// 30m, 2h, 6h, 12h (capped).
func renewBackoff(failures int) time.Duration {
	steps := []time.Duration{30 * time.Minute, 2 * time.Hour, 6 * time.Hour, 12 * time.Hour}
	if failures < 1 {
		failures = 1
	}
	if failures > len(steps) {
		failures = len(steps)
	}
	return steps[failures-1]
}

// applyPassword stores a user-supplied password on a credential (in memory;
// Encode encrypts it).
func applyPassword(credential *Credential, password string) {
	if credential == nil {
		return
	}
	credential.SetPassword(password)
}
