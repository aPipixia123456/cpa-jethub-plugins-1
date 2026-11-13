package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/collegeming/cpa-jethub-plugins/internal/abiboot"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// The 16 existing files have no password field. Parsing and encoding them
// must not invent one, and they must stay usable as probe-only credentials.
func TestLegacyCredentialWithoutPasswordRoundTrip(t *testing.T) {
	resetTestState()
	raw := []byte(`{"access_token":"0123456789abcdef0123456789abcdef","userid":"123456789012345678","phone":"13800138000","nickname":"n","expires_at":"1790000000000","type":"loomy"}`)
	credential, errParse := ParseCredential(raw)
	if errParse != nil {
		t.Fatalf("parse: %v", errParse)
	}
	if credential.HasPassword() || credential.Password() != "" || credential.PasswordEnc != "" {
		t.Fatal("a legacy file must not appear to have a password")
	}
	if credential.PlatformDisabled {
		t.Fatal("a legacy file is not platform-disabled")
	}
	encoded, errEncode := credential.Encode()
	if errEncode != nil {
		t.Fatalf("encode: %v", errEncode)
	}
	if strings.Contains(string(encoded), `"password"`) || strings.Contains(string(encoded), "password_enc") {
		t.Fatal("encoding a password-less credential must not write a password field")
	}
	again, errAgain := ParseCredential(encoded)
	if errAgain != nil {
		t.Fatalf("re-parse: %v", errAgain)
	}
	if again.Session() != credential.Session() || again.HasPassword() {
		t.Fatal("re-parsed legacy credential changed identity or gained a password")
	}
}

// A Loomy2api-style plaintext "password" field is accepted and migrated to
// password_enc on the next Encode. The plaintext key is not kept on disk
// when encryption works.
func TestLegacyPlaintextPasswordMigratesToEncrypted(t *testing.T) {
	dir := t.TempDir()
	setCredentialKeyFile(filepath.Join(dir, "credential.key"))
	t.Cleanup(func() { setCredentialKeyFile("") })

	const secret = "s3cret-for-test"
	raw := []byte(`{"access_token":"0123456789abcdef0123456789abcdef","userid":"123456789012345678","phone":"13800138000","expires_at":"1790000000000","type":"loomy","password":"` + secret + `"}`)
	credential, errParse := ParseCredential(raw)
	if errParse != nil {
		t.Fatalf("parse: %v", errParse)
	}
	if !credential.HasPassword() || credential.Password() != secret {
		t.Fatal("legacy plaintext password was not accepted")
	}
	encoded, errEncode := credential.Encode()
	if errEncode != nil {
		t.Fatalf("encode: %v", errEncode)
	}
	if strings.Contains(string(encoded), `"password"`) {
		t.Fatal("encode must not keep a plaintext password field when encryption works")
	}
	if !strings.Contains(string(encoded), `"password_enc":"v1:`) {
		t.Fatal("encode must write a v1: password_enc ciphertext")
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatal("encode must not leave the plaintext in the JSON")
	}
	info, errStat := os.Stat(filepath.Join(dir, "credential.key"))
	if errStat != nil {
		t.Fatalf("key file: %v", errStat)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode = %o, want 0600", info.Mode().Perm())
	}

	again, errAgain := ParseCredential(encoded)
	if errAgain != nil {
		t.Fatalf("re-parse: %v", errAgain)
	}
	if again.Password() != secret {
		t.Fatal("decrypted password does not match what was stored")
	}
}

func TestPasswordEncryptDecryptRoundTrip(t *testing.T) {
	dir := t.TempDir()
	setCredentialKeyFile(filepath.Join(dir, "credential.key"))
	t.Cleanup(func() { setCredentialKeyFile("") })

	cipherText, errEnc := encryptPassword("hello-loomy")
	if errEnc != nil {
		t.Fatalf("encrypt: %v", errEnc)
	}
	if !strings.HasPrefix(cipherText, passwordEncPrefix) {
		t.Fatalf("ciphertext prefix = %q, want v1:", cipherText[:min(3, len(cipherText))])
	}
	plain, errDec := decryptPassword(cipherText)
	if errDec != nil {
		t.Fatalf("decrypt: %v", errDec)
	}
	if plain != "hello-loomy" {
		t.Fatal("decrypt produced a different plaintext")
	}
	if _, errBad := decryptPassword(passwordEncPrefix + "////"); errBad == nil {
		t.Fatal("a truncated ciphertext must fail")
	}
}

func TestDeviceIDStableAndNormalised(t *testing.T) {
	a := deviceIDFor("13800138000")
	b := deviceIDFor("+86 138-0013-8000")
	c := deviceIDFor("13900139000")
	if a == "" || a != b {
		t.Fatal("the same phone in two spellings must share one device id")
	}
	if a == c {
		t.Fatal("different phones must not share a device id")
	}
	if a == "web" || !strings.Contains(a, "-") {
		t.Fatalf("device id = %q, want a UUID-shaped hash, not the literal web", a)
	}
	// UUID version 4 / variant bits: 13th hex nibble is 4, 17th is 8-b.
	// Format: 8-4-4-4-12, version sits at the first char of the third group.
	parts := strings.Split(a, "-")
	if len(parts) != 5 || !strings.HasPrefix(parts[2], "4") {
		t.Fatalf("device id = %q, want a version-4 UUID", a)
	}
	if deviceIDFor("") != "" {
		t.Fatal("an empty seed must not produce an id")
	}
}

func TestGatewayHeadersUseOfficialClientValues(t *testing.T) {
	resetTestState()
	setSettings(DefaultConfig())
	credential := sampleCredential(t)
	chat := chatHeaders(credential)
	if got := chat.Get("User-Agent"); got != AccountUA {
		t.Fatalf("chat UA = %q, want %q", got, AccountUA)
	}
	if got := chat["loomy-version"]; len(got) != 1 || got[0] != DefaultLoomyVersion {
		t.Fatalf("chat loomy-version = %#v, want lowercase %q", got, DefaultLoomyVersion)
	}
	biz := businessHeaders(credential, false)
	if got := biz.Get("User-Agent"); got != AccountUA {
		t.Fatalf("business UA = %q, want %q", got, AccountUA)
	}
	if got := biz["loomy-version"]; len(got) != 1 || got[0] != DefaultLoomyVersion {
		t.Fatalf("business loomy-version = %#v, want %q", got, DefaultLoomyVersion)
	}
	if biz.Get("Authorization") != "" {
		t.Fatal("business headers must still omit Authorization")
	}

	cfg := DefaultConfig()
	cfg.UserAgent = "Loomy|Custom|Test"
	cfg.LoomyVersion = "9.9.9"
	setSettings(cfg)
	t.Cleanup(func() { setSettings(DefaultConfig()) })
	custom := chatHeaders(credential)
	if custom.Get("User-Agent") != "Loomy|Custom|Test" {
		t.Fatalf("custom UA = %q", custom.Get("User-Agent"))
	}
	if custom["loomy-version"][0] != "9.9.9" {
		t.Fatalf("custom version = %#v", custom["loomy-version"])
	}
}

func TestRenewBackoffAndWindow(t *testing.T) {
	if got := renewBackoff(1); got != 30*time.Minute {
		t.Fatalf("backoff(1) = %s, want 30m", got)
	}
	if got := renewBackoff(2); got != 2*time.Hour {
		t.Fatalf("backoff(2) = %s, want 2h", got)
	}
	if got := renewBackoff(3); got != 6*time.Hour {
		t.Fatalf("backoff(3) = %s, want 6h", got)
	}
	if got := renewBackoff(4); got != 12*time.Hour {
		t.Fatalf("backoff(4) = %s, want 12h", got)
	}
	if got := renewBackoff(99); got != 12*time.Hour {
		t.Fatalf("backoff(99) = %s, want the 12h cap", got)
	}

	now := time.Now()
	bare := sampleCredential(t)
	if shouldRenewByPassword(bare, true, now) {
		t.Fatal("a credential without a password must not auto-renew")
	}
	bare.SetPassword("x")
	// 14-day default session is well outside the 4-day window.
	if shouldRenewByPassword(bare, true, now) {
		t.Fatal("a fresh 14-day session must not renew yet")
	}
	if !shouldRenewByPassword(bare, false, now) {
		t.Fatal("a failed probe must trigger password renew when a password is stored")
	}
	soon := &Credential{AccessToken: "s", Phone: "13800138000", ExpiresAt: millisString(now.Add(3 * 24 * time.Hour))}
	soon.SetPassword("x")
	if !shouldRenewByPassword(soon, true, now) {
		t.Fatal("fewer than 4 days remaining must trigger a renew")
	}
}

func millisString(t time.Time) string {
	return timeUnixMilli(t)
}

func timeUnixMilli(t time.Time) string {
	return itoaInt64(t.UnixMilli())
}

func itoaInt64(n int64) string {
	return strings.TrimSpace(strings.ReplaceAll(jsonNumber(n), "\n", ""))
}

func jsonNumber(n int64) string {
	raw, _ := json.Marshal(n)
	return string(raw)
}

func TestEnvelope100003IsAccountDisabled(t *testing.T) {
	parsed, errParse := parseEnvelope([]byte(`{"ok":false,"code":"100003","desc":"账号已停用"}`))
	if errParse != nil {
		t.Fatalf("parse: %v", errParse)
	}
	if !parsed.isAccountDisabled() || parsed.isAuthExpired() {
		t.Fatal("100003 must be platform-disabled, not session-expired")
	}
	errFail := envelopeFailure("探测", parsed)
	if statusOf(errFail, 0) != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", statusOf(errFail, 0))
	}
	if !isAccountDisabledErr(errFail) || isAuthExpiredErr(errFail) {
		t.Fatal("the error must classify as account-disabled, not auth-expired")
	}
	if strings.Contains(errFail.Error(), "请重新登录") {
		t.Fatal("100003 must not advise a re-login")
	}
}

func TestInferFailure100003ParksWithoutRelogin(t *testing.T) {
	fake := newFakeHost()
	fake.do = func(request abiboot.HTTPDoRequest) (*pluginapi.HTTPResponse, error) {
		return httpResponse(200, `{"ok":false,"code":"100003","desc":"账号已停用"}`), nil
	}
	fake.install(t)

	credential := sampleCredential(t)
	_, errExecute := handleExecutorExecute(testHost(), executorPayload(t, credential, "MiniMax-M3", `{}`))
	if errExecute == nil {
		t.Fatal("100003 must fail the request")
	}
	if statusOf(errExecute, 0) != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 so CPA switches accounts", statusOf(errExecute, 0))
	}
	if !isAccountDisabledErr(errExecute) {
		t.Fatalf("error = %v, want account_disabled", errExecute)
	}
	if fake.saveWrites() < 1 {
		t.Fatal("100003 must stamp the credential as platform-disabled")
	}
}

func TestInferFailure403DoesNotRelogin(t *testing.T) {
	resetRiskBreaker()
	fake := newFakeHost()
	fake.do = func(request abiboot.HTTPDoRequest) (*pluginapi.HTTPResponse, error) {
		return httpResponse(http.StatusForbidden, `{"error":{"message":"风控"}}`), nil
	}
	fake.install(t)

	_, errExecute := handleExecutorExecute(testHost(), executorPayload(t, sampleCredential(t), "MiniMax-M3", `{}`))
	if errExecute == nil {
		t.Fatal("HTTP 403 must fail")
	}
	if statusOf(errExecute, 0) != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (not 401)", statusOf(errExecute, 0))
	}
	if isAuthExpiredErr(errExecute) {
		t.Fatal("a 403 must not be treated as session expiry")
	}
	if fake.saveWrites() != 0 {
		t.Fatal("a 403 must not rewrite the credential or trigger a re-login")
	}
}

func TestRiskBreakerPausesAfterTwoAccounts(t *testing.T) {
	resetRiskBreaker()
	cfg := DefaultConfig()
	cfg.RiskPauseSec = 1800
	cfg.riskPauseSet = true
	setSettings(cfg)
	t.Cleanup(func() {
		resetRiskBreaker()
		setSettings(DefaultConfig())
	})

	noteRisk("acct-a", "403")
	if pauseRemaining() > 0 {
		t.Fatal("one account must not trip the breaker")
	}
	noteRisk("acct-b", "403")
	left := pauseRemaining()
	if left < 1700*time.Second {
		t.Fatalf("pause remaining = %s, want ~1800s", left)
	}
	if err := riskPausedError(); err == nil || statusOf(err, 0) != http.StatusTooManyRequests {
		t.Fatalf("paused error = %v, want 429", err)
	}
}

func TestAuthRefresh100003ParksAndDoesNotRelogin(t *testing.T) {
	fake := newFakeHost()
	var probed int
	fake.do = func(request abiboot.HTTPDoRequest) (*pluginapi.HTTPResponse, error) {
		probed++
		if strings.Contains(request.URL, GetPuKeyPath) || strings.Contains(request.URL, ByPwdPath) {
			t.Fatal("100003 must not start a password login")
		}
		return httpResponse(200, `{"ok":false,"code":"100003","desc":"账号已停用"}`), nil
	}
	fake.install(t)

	credential := sampleCredential(t)
	credential.SetPassword("stored-secret")
	storage, errEncode := credential.Encode()
	if errEncode != nil {
		t.Fatalf("encode: %v", errEncode)
	}
	_, errRefresh := handleAuthRefresh(testHost(), mustJSON(t, pluginapi.AuthRefreshRequest{
		AuthID: "loomy-acct.json", StorageJSON: storage,
	}))
	if errRefresh == nil {
		t.Fatal("100003 must fail the refresh")
	}
	if statusOf(errRefresh, 0) != http.StatusForbidden || !isAccountDisabledErr(errRefresh) {
		t.Fatalf("error = %v, want 403 account_disabled", errRefresh)
	}
	if probed != 1 {
		t.Fatalf("issued %d probes, want 1 (the points read only)", probed)
	}
}

func TestAuthRefresh403DoesNotRelogin(t *testing.T) {
	resetRiskBreaker()
	fake := newFakeHost()
	fake.do = func(request abiboot.HTTPDoRequest) (*pluginapi.HTTPResponse, error) {
		if strings.Contains(request.URL, GetPuKeyPath) || strings.Contains(request.URL, ByPwdPath) {
			t.Fatal("a 403 probe must not start a password login")
		}
		return httpResponse(http.StatusForbidden, `{"error":{"message":"风控"}}`), nil
	}
	fake.install(t)

	credential := sampleCredential(t)
	credential.SetPassword("stored-secret")
	storage, _ := credential.Encode()
	_, errRefresh := handleAuthRefresh(testHost(), mustJSON(t, pluginapi.AuthRefreshRequest{StorageJSON: storage}))
	if errRefresh == nil || statusOf(errRefresh, 0) != http.StatusForbidden {
		t.Fatalf("error = %v, want 403", errRefresh)
	}
	if isAuthExpiredErr(errRefresh) {
		t.Fatal("403 is not session expiry")
	}
}

func TestAuthRefreshPasswordRenewAndBackoff(t *testing.T) {
	priv, errKey := rsa.GenerateKey(rand.Reader, 2048)
	if errKey != nil {
		t.Fatalf("rsa: %v", errKey)
	}
	der, errDER := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if errDER != nil {
		t.Fatalf("marshal: %v", errDER)
	}
	pukey := base64.StdEncoding.EncodeToString(der)

	fake := newFakeHost()
	var byPwdCalls, puKeyCalls int
	fake.do = func(request abiboot.HTTPDoRequest) (*pluginapi.HTTPResponse, error) {
		switch {
		case strings.Contains(request.URL, PointsRecordsPath):
			return httpResponse(200, `{"code":"000000","data":{"balance":1,"dailyBalance":1,"availableBalance":2}}`), nil
		case strings.Contains(request.URL, GetPuKeyPath):
			puKeyCalls++
			return httpResponse(200, `{"code":"000000","data":{"pukey":"`+pukey+`","rcode":"RC1"}}`), nil
		case strings.Contains(request.URL, ByPwdPath):
			byPwdCalls++
			if byPwdCalls == 1 {
				return httpResponse(200, `{"ok":false,"code":"030002","desc":"密码错误"}`), nil
			}
			return httpResponse(200, `{"code":"000000","data":{"session":"abcdefabcdefabcdefabcdefabcdefab","userid":"123456789012345678"}}`), nil
		default:
			return httpResponse(200, `{"code":"000000","data":{}}`), nil
		}
	}
	fake.install(t)

	now := time.Now()
	credential := buildCredential("0123456789abcdef0123456789abcdef", "123456789012345678", "13800138000", "", DefaultConfig(), now.Add(-11*24*time.Hour))
	// Expiry is ~3 days from now (14-day TTL starting 11 days ago).
	credential.SetPassword("stored-secret")
	storage, errEncode := credential.Encode()
	if errEncode != nil {
		t.Fatalf("encode: %v", errEncode)
	}

	value, errRefresh := handleAuthRefresh(testHost(), mustJSON(t, pluginapi.AuthRefreshRequest{
		AuthID: "loomy-acct.json", StorageJSON: storage,
	}))
	if errRefresh != nil {
		t.Fatalf("first refresh (failed password) should schedule a backoff, got error: %v", errRefresh)
	}
	first := decodeResult[pluginapi.AuthRefreshResponse](t, value)
	if first.NextRefreshAfter.IsZero() || first.NextRefreshAfter.Before(now.Add(20*time.Minute)) {
		t.Fatalf("next = %s, want ~30m backoff", first.NextRefreshAfter)
	}
	retried, errParse := ParseCredential(first.Auth.StorageJSON)
	if errParse != nil {
		t.Fatalf("parse: %v", errParse)
	}
	if retried.RenewFailures != 1 {
		t.Fatalf("renew_failures = %d, want 1", retried.RenewFailures)
	}
	if retried.Session() != credential.Session() {
		t.Fatal("a failed password login must leave the existing session in place")
	}
	if byPwdCalls != 1 || puKeyCalls != 1 {
		t.Fatalf("puKey=%d byPwd=%d, want 1 each on the first attempt", puKeyCalls, byPwdCalls)
	}

	// Second attempt succeeds and clears the failure count.
	value2, errSecond := handleAuthRefresh(testHost(), mustJSON(t, pluginapi.AuthRefreshRequest{
		AuthID: "loomy-acct.json", StorageJSON: first.Auth.StorageJSON,
	}))
	if errSecond != nil {
		t.Fatalf("second refresh: %v", errSecond)
	}
	second := decodeResult[pluginapi.AuthRefreshResponse](t, value2)
	fresh, errFresh := ParseCredential(second.Auth.StorageJSON)
	if errFresh != nil {
		t.Fatalf("parse fresh: %v", errFresh)
	}
	if fresh.Session() != "abcdefabcdefabcdefabcdefabcdefab" {
		t.Fatal("successful password login must store the new session")
	}
	if fresh.RenewFailures != 0 {
		t.Fatalf("renew_failures = %d, want 0 after success", fresh.RenewFailures)
	}
	if !fresh.HasPassword() || fresh.Password() != "stored-secret" {
		t.Fatal("the stored password must survive a successful renew")
	}
	if strings.Contains(string(second.Auth.StorageJSON), "stored-secret") {
		t.Fatal("the new auth file must not contain the plaintext password")
	}
}

func TestLoginByPasswordRSARoundTrip(t *testing.T) {
	priv, errKey := rsa.GenerateKey(rand.Reader, 2048)
	if errKey != nil {
		t.Fatalf("rsa: %v", errKey)
	}
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pukey := base64.StdEncoding.EncodeToString(der)

	const wantPassword = "pw-value"
	var decryptedOK bool
	fake := newFakeHost()
	fake.do = func(request abiboot.HTTPDoRequest) (*pluginapi.HTTPResponse, error) {
		if strings.Contains(request.URL, GetPuKeyPath) {
			return httpResponse(200, `{"code":"000000","data":{"pukey":"`+pukey+`","rcode":"R9"}}`), nil
		}
		if strings.Contains(request.URL, ByPwdPath) {
			var body struct {
				Base struct {
					UA       string `json:"ua"`
					DeviceID string `json:"devid"`
				} `json:"base"`
				Param struct {
					LoginID, Password, RCode string
					Type, Expire             int
				} `json:"param"`
			}
			if err := json.Unmarshal(request.Body, &body); err != nil {
				t.Fatalf("decode byPwd body: %v", err)
			}
			if body.Base.UA != AccountUA {
				t.Fatalf("login ua = %q, want the gateway UA", body.Base.UA)
			}
			if body.Base.DeviceID != deviceIDFor("13800138000") {
				t.Fatalf("login devid = %q, want the stable hash", body.Base.DeviceID)
			}
			if body.Param.RCode != "R9" || body.Param.Type != 1 {
				t.Fatalf("param rcode/type unexpected")
			}
			enc, errDec := base64.StdEncoding.DecodeString(body.Param.Password)
			if errDec != nil {
				t.Fatal("encrypted password was not base64")
			}
			plain, errOpen := rsa.DecryptPKCS1v15(rand.Reader, priv, enc)
			if errOpen != nil {
				t.Fatal("account host could not decrypt the password")
			}
			if string(plain) != wantPassword {
				t.Fatal("decrypted password does not match the input")
			}
			decryptedOK = true
			if strings.Contains(string(request.Body), wantPassword) {
				t.Fatal("the wire body must not contain the plaintext password")
			}
			return httpResponse(200, `{"code":"000000","data":{"session":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","userid":"123456789012345678"}}`), nil
		}
		return httpResponse(500, "unexpected"), nil
	}
	fake.install(t)

	session, userID, errLogin := loginByPassword(testHost(), DefaultConfig(), "13800138000", wantPassword, time.Now())
	if errLogin != nil {
		t.Fatalf("loginByPassword: %v", errLogin)
	}
	if !decryptedOK || session == "" || userID == "" {
		t.Fatal("password login did not complete")
	}
}

func TestSMSAutoAcceptsPasswordInJSON(t *testing.T) {
	session := startLoginSession(DefaultConfig(), "")
	session.notePhone("13800138000")
	if session.passwordValue() != "" {
		t.Fatal("a fresh session has no password")
	}
	session.notePassword("from-json")
	if session.passwordValue() != "from-json" {
		t.Fatal("notePassword did not stick")
	}
}

func TestChmodCredentialFileSets0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acct.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	chmodCredentialFile(path)
	info, errStat := os.Stat(path)
	if errStat != nil {
		t.Fatalf("stat: %v", errStat)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 0600", info.Mode().Perm())
	}
	chmodCredentialFile("") // must be a no-op
}

func TestAccountIdentityMatchesGatewayUA(t *testing.T) {
	cfg := DefaultConfig()
	id := identityFor(cfg, "13800138000")
	if id.UA != AccountUA {
		t.Fatalf("ua = %q, want %q", id.UA, AccountUA)
	}
	if id.DeviceID != deviceIDFor("13800138000") {
		t.Fatalf("devid = %q, want the hashed id", id.DeviceID)
	}
	cfg.UserAgent = "Loomy|Desktop|Electron|Windows"
	id2 := identityFor(cfg, "13800138000")
	if id2.UA != "Loomy|Desktop|Electron|Windows" {
		t.Fatalf("overridden ua = %q", id2.UA)
	}
}
