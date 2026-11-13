package main

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/collegeming/cpa-jethub-plugins/internal/abiboot"
	"github.com/collegeming/cpa-jethub-plugins/internal/jethub/authfile"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// refreshLead is how long before the local expiry a probe is scheduled. It only
// decides WHEN the host asks; this provider has no way to extend a session.
const refreshLead = 24 * time.Hour

// unsafeFileNameChars keeps an auth file name inside [A-Za-z0-9._@-].
var unsafeFileNameChars = regexp.MustCompile(`[^A-Za-z0-9._@-]+`)

// handleAuthIdentifier advertises the provider key this plugin owns.
func handleAuthIdentifier(_ *abiboot.Host, _ json.RawMessage) (any, error) {
	return abiboot.IdentifierReply(ProviderKey), nil
}

// handleAuthParse recognises an auth file already present in the auth directory.
func handleAuthParse(_ *abiboot.Host, raw json.RawMessage) (any, error) {
	request, errDecode := abiboot.Decode[pluginapi.AuthParseRequest](raw)
	if errDecode != nil {
		return nil, errDecode
	}
	if request.Provider != "" && request.Provider != ProviderKey && request.Provider != legacyProviderKey {
		return pluginapi.AuthParseResponse{Handled: false}, nil
	}
	credential, errParse := ParseCredential(request.RawJSON)
	if errParse != nil {
		// Not one of ours: let the host try other providers.
		return pluginapi.AuthParseResponse{Handled: false}, nil
	}
	auth, errAuth := authDataFor(credential, authNameForHost(request.FileName, request.Path, "", credential))
	if errAuth != nil {
		return nil, errAuth
	}
	return pluginapi.AuthParseResponse{Handled: true, Auth: auth}, nil
}

// handleAuthRefresh probes the credential and, when a password is stored,
// renews the session the way Loomy2api-CPAMC does:
//
//   - 100003 (platform disabled): park the credential, return 403, do not
//     re-login;
//   - 403 / TM.* risk control: record a risk hit, return 403, do not re-login;
//   - password present: probe, then re-login when remaining life is under 4
//     days or the probe failed; failures back off 30m → 2h → 6h → 12h;
//   - no password: probe only, same as v0.1.25 (the 16 existing files).
//
// Loomy still has no refresh_token; password re-login is a full sign-in,
// not a token rotation.
func handleAuthRefresh(h *abiboot.Host, raw json.RawMessage) (any, error) {
	request, errDecode := abiboot.Decode[pluginapi.AuthRefreshRequest](raw)
	if errDecode != nil {
		return nil, errDecode
	}
	credential, errParse := ParseCredential(request.StorageJSON)
	if errParse != nil {
		return nil, errParse
	}
	fileName := authNameForHost(request.AuthID, request.Attributes["path"], request.Attributes["source"], credential)
	cfg := settings()
	now := time.Now()

	if credential.PlatformDisabled {
		markPlatformDisabled(h, fileName, credential)
		return nil, accountDisabledError("探测", "账号此前已被平台停用")
	}

	errProbe := probeCredential(h, credential, cfg)
	if isAccountDisabledErr(errProbe) {
		markPlatformDisabled(h, fileName, credential)
		return nil, errProbe
	}
	if errProbe != nil && isRiskRejection(statusOf(errProbe, 0), "", errProbe.Error()) {
		noteRisk(credential.maskedPhone(), truncate(errProbe.Error(), 200))
		return nil, riskControlError(statusOf(errProbe, http.StatusForbidden), truncate(errProbe.Error(), 200))
	}

	alive := errProbe == nil
	if shouldRenewByPassword(credential, alive, now) {
		return refreshByPassword(h, cfg, credential, fileName, now)
	}
	if errProbe != nil {
		return nil, errProbe
	}
	auth, errAuth := authDataFor(credential, fileName)
	if errAuth != nil {
		return nil, errAuth
	}
	return pluginapi.AuthRefreshResponse{
		Auth:             auth,
		NextRefreshAfter: nextProbeAfter(credential, now),
	}, nil
}

// refreshByPassword performs one password re-login and schedules the next
// attempt (or the 30m/2h/6h/12h backoff on failure).
func refreshByPassword(h *abiboot.Host, cfg Config, credential *Credential, fileName string, now time.Time) (any, error) {
	session, userID, errLogin := loginByPassword(h, cfg, credential.Phone, credential.Password(), now)
	if errLogin != nil {
		if isAccountDisabledErr(errLogin) {
			markPlatformDisabled(h, fileName, credential)
			return nil, errLogin
		}
		if isRiskRejection(statusOf(errLogin, 0), "", errLogin.Error()) {
			noteRisk(credential.maskedPhone(), truncate(errLogin.Error(), 200))
			return nil, riskControlError(statusOf(errLogin, http.StatusForbidden), truncate(errLogin.Error(), 200))
		}
		credential.RenewFailures++
		auth, errAuth := authDataFor(credential, fileName)
		if errAuth != nil {
			return nil, errLogin
		}
		next := now.Add(renewBackoff(credential.RenewFailures))
		auth.NextRefreshAfter = next
		if h != nil {
			if saved, errSave := h.SaveAuth(auth.FileName, auth.StorageJSON); errSave == nil && saved != nil {
				chmodCredentialFile(saved.Path)
			}
		}
		return pluginapi.AuthRefreshResponse{Auth: auth, NextRefreshAfter: next}, nil
	}
	password := credential.Password()
	proxy := credential.ProxyURL
	fresh := buildCredential(session, firstNonEmpty(userID, credential.UserID), credential.Phone, credential.Nickname, cfg, now)
	fresh.SetPassword(password)
	fresh.ProxyURL = proxy
	fresh.RenewFailures = 0
	auth, errAuth := authDataFor(fresh, fileName)
	if errAuth != nil {
		return nil, errAuth
	}
	if h != nil {
		if saved, errSave := h.SaveAuth(auth.FileName, auth.StorageJSON); errSave == nil && saved != nil {
			chmodCredentialFile(saved.Path)
		}
	}
	return pluginapi.AuthRefreshResponse{
		Auth:             auth,
		NextRefreshAfter: nextProbeAfter(fresh, now),
	}, nil
}

// markPlatformDisabled stamps the credential and asks the host to park it
// so CPA stops routing to this account. It never attempts a re-login.
func markPlatformDisabled(h *abiboot.Host, fileName string, credential *Credential) {
	if credential != nil {
		credential.PlatformDisabled = true
	}
	if h == nil || strings.TrimSpace(fileName) == "" {
		return
	}
	overlay, errMarshal := json.Marshal(map[string]any{
		"disabled":          true,
		"disabled_by":       "loomy:platform",
		"platform_disabled": true,
	})
	if errMarshal != nil {
		return
	}
	if saved, errSave := h.SaveAuth(fileName, overlay); errSave == nil && saved != nil {
		chmodCredentialFile(saved.Path)
	}
}

// parkIfAccountDisabled persists a 100003 platform ban so CPA stops
// routing to the account. It is a no-op for any other error (including
// nil) and never starts a re-login. The same error is returned unchanged.
func parkIfAccountDisabled(h *abiboot.Host, fileName string, credential *Credential, err error) error {
	if isAccountDisabledErr(err) {
		markPlatformDisabled(h, fileName, credential)
	}
	return err
}

// authFileName is the host identity used to park a credential: the auth
// file name when the host provides one, otherwise the runtime index.
func authFileName(entry pluginapi.HostAuthFileEntry) string {
	return firstNonEmpty(strings.TrimSpace(entry.Name), strings.TrimSpace(entry.AuthIndex), strings.TrimSpace(entry.ID))
}

// nextProbeAfter decides when the host should probe again.
//
// A credential with no local expiry gets no schedule at all: there is nothing to
// count down to, and the server stays the only authority. A locally expired
// credential is still probed on the reference's 30-minute health cadence
// (`index.ts:490`) instead of immediately, because the local clock is not
// evidence — the source deliberately keeps using a possibly-stale credential
// (`loomy.ts:184-193`).
func nextProbeAfter(credential *Credential, now time.Time) time.Time {
	expiry := credential.Expiry()
	if expiry.IsZero() {
		return time.Time{}
	}
	if candidate := expiry.Add(-refreshLead); candidate.After(now) {
		return candidate
	}
	return now.Add(time.Duration(CredentialHealthIntervalMS) * time.Millisecond)
}

// authNameForHost resolves the auth file name the host already uses for this
// credential: the name it supplies on `auth.parse` (the file it read the
// credential from) or on the probe the host calls `auth.refresh` (the auth
// record id, which for a file-backed credential is that same file name), and
// failing both, the `path`/`source` attribute naming that file.
//
// The probe returns the credential unchanged, so a derived name would be
// harmless today — but Loomy's name comes from the phone number, and a
// credential whose phone and user id are both missing would fall back to a
// constant ("account") shared by every such account. Keeping the host's name
// means the probe can never move a credential into another file.
func authNameForHost(incoming, path, source string, credential *Credential) string {
	return authfile.Name(func() string { return defaultAuthFileName(credential) }, incoming, path, source)
}

// authDataFor converts a credential into the host-facing AuthData record.
func authDataFor(credential *Credential, fileName string) (pluginapi.AuthData, error) {
	storage, errEncode := credential.Encode()
	if errEncode != nil {
		return pluginapi.AuthData{}, errEncode
	}
	if fileName == "" {
		fileName = defaultAuthFileName(credential)
	}
	label := credential.displayLabel()
	prefix := modelPrefixFor(credential)
	if !settings().ModelPrefix {
		prefix = ""
	}
	refreshable := credential.HasPassword() && !credential.PlatformDisabled
	metadata := map[string]any{
		"userid":     credential.UserID,
		"phone":      credential.Phone,
		"expires_at": credential.ExpiresAtMS(),
		// Password-backed credentials can be re-logged-in automatically;
		// there is still no refresh_token. The flag only tells the manager
		// whether auto-renew is available.
		"refreshable":       refreshable,
		"has_password":      credential.HasPassword(),
		"platform_disabled": credential.PlatformDisabled,
	}
	if expiry := credential.Expiry(); !expiry.IsZero() {
		metadata["expires_at_rfc3339"] = expiry.UTC().Format(time.RFC3339)
	}
	return pluginapi.AuthData{
		Provider:    ProviderKey,
		ID:          fileName,
		FileName:    fileName,
		Label:       label,
		Prefix:      prefix,
		ProxyURL:    credential.ProxyURL,
		Disabled:    credential.PlatformDisabled,
		StorageJSON: storage,
		Metadata:    metadata,
		// NOTE: do not use the reserved host attribute name "api_key" here. The
		// host reads it in Auth.AuthKind() and would classify the credential as an
		// API key, which silently disables the manager's model alias and
		// excluded-model rules for this provider.
		Attributes: map[string]string{
			"account":     label,
			"credential":  ProviderKey,
			"userid":      credential.UserID,
			"refreshable": boolString(refreshable),
		},
		NextRefreshAfter: nextProbeAfter(credential, time.Now()),
	}, nil
}

// defaultAuthFileName derives a stable auth-file name for an account.
//
// It is deterministic on purpose: the management page saves the credential when
// the code verifies and `auth.login.poll` returns the same FileName, so a host
// that saves the poll result again overwrites that file instead of creating a
// second credential for the same account.
func defaultAuthFileName(credential *Credential) string {
	identity := credential.displayLabel()
	identity = unsafeFileNameChars.ReplaceAllString(strings.TrimSpace(identity), "-")
	identity = strings.Trim(identity, "-")
	if identity == "" {
		identity = "account"
	}
	if len(identity) > 48 {
		identity = identity[:48]
	}
	return ProviderKey + "-" + identity + ".json"
}

// credentialAdvice is appended to every dead-session answer: there is no refresh
// token to rotate, so the only remedy is a fresh login (WeChat scan, or SMS).
func credentialAdvice() string {
	return "（Loomy 没有 refresh_token；已保存密码的账号会自动重登，否则请用自动接码、手动短信或密码登录）"
}

// modelPrefixFor returns the model prefix shared by every Loomy account.
// By default all accounts publish under one fixed prefix ("loomy/<model>") so
// clients can address the pool with a single, stable name. Setting
// model_prefix_name to an empty string restores the old per-account prefix
// (first 8 characters of the account userid).
func modelPrefixFor(credential *Credential) string {
	if name := strings.Trim(strings.TrimSpace(settings().ModelPrefixName), "/"); name != "" {
		return name
	}
	prefix := ""
	if credential != nil {
		prefix = strings.TrimSpace(credential.UserID)
	}
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	return prefix
}
