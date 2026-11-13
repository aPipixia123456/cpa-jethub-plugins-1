package main

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/collegeming/cpa-jethub-plugins/internal/abiboot"
	"github.com/collegeming/cpa-jethub-plugins/internal/jethub/plugui"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// Password management pages live on POST-capable `/v0/management/loomy/*`
// routes, NOT on the GET-only resource mount. The resource login page only
// links here; it never contains a <form> (see TestNoPageContainsAForm).
//
//	GET/POST /loomy/pwdlogin  phone + password login
//	GET/POST /loomy/pwdsave   attach a password to the in-flight SMS session
//	                          or to an already-saved credential
//
// The password is read from the POST body (form or JSON) and is never
// written into a query string, a log line, or a rendered page.

const (
	passwordLoginPath = "/v0/management/loomy/pwdlogin"
	passwordSavePath  = "/v0/management/loomy/pwdsave"

	passwordLimitNote = "上游没有提供设置或修改密码的接口。这里填写的是该账号已经在官方 Loomy 客户端设置过的密码，" +
		"仅加密保存在本地凭据里（AES-256-GCM，密钥文件权限 0600），用于手机号+密码登录和自动续登。" +
		"刚通过接码注册、从未在官方客户端设过密码的号码，保存后也无法用密码登录上游。"
)

func handlePasswordLoginPage(h *abiboot.Host, request pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	if request.Method == http.MethodPost {
		return handlePasswordLoginSubmit(h, request)
	}
	return renderPasswordLoginForm(request, "", "")
}

func handlePasswordSavePage(h *abiboot.Host, request pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	if request.Method == http.MethodPost {
		return handlePasswordSaveSubmit(h, request)
	}
	return renderPasswordSaveForm(request, "", "")
}

func renderPasswordLoginForm(request pluginapi.ManagementRequest, notice, tone string) pluginapi.ManagementResponse {
	phone := htmlEsc(postedOrQuery(request, "phone"))
	state := htmlEsc(postedOrQuery(request, "state"))
	body := []template.HTML{}
	if notice != "" {
		body = append(body, plugui.Notice(tone, notice))
	}
	body = append(body, plugui.Notice("warning", passwordLimitNote))
	body = append(body, passwordFormHTML(passwordLoginPath, state, phone, "登录并保存",
		"phone", "手机号（11 位）", true))
	body = append(body, plugui.Card("其他方式", plugui.Group(plugui.Note("接码或手动短信登录仍在登录页。")),
		plugui.Action{Label: "返回自动接码登录", Path: loginResourcePath},
		plugui.Action{Label: "返回状态", Path: "/v0/resource/plugins/loomy-provider/status"},
	))
	return pluguiPage("Loomy 密码登录", body...)
}

func renderPasswordSaveForm(request pluginapi.ManagementRequest, notice, tone string) pluginapi.ManagementResponse {
	phone := htmlEsc(postedOrQuery(request, "phone"))
	state := htmlEsc(postedOrQuery(request, "state"))
	auth := htmlEsc(postedOrQuery(request, "auth"))
	body := []template.HTML{}
	if notice != "" {
		body = append(body, plugui.Notice(tone, notice))
	}
	body = append(body, plugui.Notice("warning", passwordLimitNote))
	extra := ""
	if auth != "" {
		extra = `<input type="hidden" name="auth" value="` + auth + `">`
	}
	form := passwordFormHTML(passwordSavePath, state, phone, "保存密码（不重新登录）",
		"phone", "手机号（可留空，若已在登录会话中）", false)
	if extra != "" {
		// Insert the extra hidden field just after the opening form tag.
		form = template.HTML(strings.Replace(string(form), ">", ">"+extra, 1))
	}
	body = append(body, form)
	body = append(body, plugui.Card("", plugui.Group(),
		plugui.Action{Label: "返回登录", Path: loginResourcePath, Query: "state=" + postedOrQuery(request, "state")},
		plugui.Action{Label: "返回状态", Path: "/v0/resource/plugins/loomy-provider/status"},
	))
	return pluguiPage("Loomy 保存续登密码", body...)
}

func passwordFormHTML(action, state, phone, submit, phoneName, phoneLabel string, phoneRequired bool) template.HTML {
	req := ""
	if phoneRequired {
		req = " required"
	}
	return template.HTML(`<section class="card"><h2>` + htmlEsc(submit) + `</h2>` +
		`<form method="post" action="` + htmlEsc(action) + `" autocomplete="off">` +
		`<input type="hidden" name="state" value="` + htmlEsc(state) + `">` +
		`<dl class="fields">` +
		`<dt>` + htmlEsc(phoneLabel) + `</dt>` +
		`<dd><input name="` + htmlEsc(phoneName) + `" type="tel" inputmode="numeric" value="` + htmlEsc(phone) + `" ` +
		`style="width:100%;font:inherit;padding:6px 10px;border-radius:6px;border:1px solid var(--app-border,#d8dee4);background:var(--app-input-bg,#f6f8fa);color:inherit"` + req + `></dd>` +
		`<dt>密码</dt>` +
		`<dd><input name="password" type="password" autocomplete="current-password" ` +
		`style="width:100%;font:inherit;padding:6px 10px;border-radius:6px;border:1px solid var(--app-border,#d8dee4);background:var(--app-input-bg,#f6f8fa);color:inherit" required></dd>` +
		`</dl>` +
		`<div class="actions"><button class="btn primary" type="submit">` + htmlEsc(submit) + `</button></div>` +
		`</form></section>`)
}

func handlePasswordLoginSubmit(h *abiboot.Host, request pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	phone, password, state := postedCredentials(request)
	if wantsJSON(request) && (phone == "" || password == "") {
		return jsonManagementResponse(http.StatusBadRequest, map[string]any{"ok": false, "error": "需要 phone 和 password"})
	}
	if !validPhone(phone) {
		return renderPasswordLoginForm(request, "手机号格式不正确（需要 11 位大陆手机号）", "danger")
	}
	if password == "" {
		return renderPasswordLoginForm(request, "请填写密码", "danger")
	}
	cfg := settings()
	sessionToken, userID, errLogin := loginByPassword(h, cfg, phone, password, time.Now())
	if errLogin != nil {
		// Never include the password; envelopeFailure already carries the
		// server desc (e.g. "密码错误") without secrets.
		if wantsJSON(request) {
			return jsonManagementResponse(statusOf(errLogin, http.StatusBadGateway), map[string]any{
				"ok": false, "error": errLogin.Error(),
			})
		}
		return renderPasswordLoginForm(request, errLogin.Error(), "danger")
	}
	credential := buildCredential(sessionToken, userID, phone, "", cfg, time.Now())
	credential.SetPassword(password)
	var session *loginSession
	if state != "" {
		session, _ = lookupLoginSession(state)
	}
	if session == nil {
		session = startLoginSession(cfg, phone)
	}
	session.notePassword(password)
	if errStore := storeLoginCredential(h, cfg, session, credential, "密码登录成功，账号已保存"); errStore != nil {
		if wantsJSON(request) {
			return jsonManagementResponse(statusOf(errStore, http.StatusBadGateway), map[string]any{
				"ok": false, "error": errStore.Error(),
			})
		}
		return renderPasswordLoginForm(request, errStore.Error(), "danger")
	}
	if wantsJSON(request) {
		return jsonManagementResponse(http.StatusOK, map[string]any{
			"ok":           true,
			"label":        credential.displayLabel(),
			"phone_masked": credential.maskedPhone(),
			"auth_file":    session.fileNameValue(),
			"has_password": true,
		})
	}
	return loginSuccessPage(session, credential, "手机号+密码")
}

func handlePasswordSaveSubmit(h *abiboot.Host, request pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	phone, password, state := postedCredentials(request)
	if password == "" {
		if wantsJSON(request) {
			return jsonManagementResponse(http.StatusBadRequest, map[string]any{"ok": false, "error": "请填写密码"})
		}
		return renderPasswordSaveForm(request, "请填写密码", "danger")
	}
	// 1. Attach to an in-flight login session so the subsequent SMS verify
	//    writes the password into the new credential.
	if state != "" {
		if session, ok := lookupLoginSession(state); ok && session != nil {
			session.notePassword(password)
			if wantsJSON(request) {
				return jsonManagementResponse(http.StatusOK, map[string]any{"ok": true, "attached": "session"})
			}
			return pluguiPage("Loomy 保存续登密码",
				plugui.Notice("success", "密码已记住，完成接码或短信验证后会随凭据一起加密保存。"),
				plugui.Card("", plugui.Group(),
					plugui.Action{Label: "继续自动接码", Path: loginResourcePath, Query: "action=auto&state=" + state, Kind: "primary"},
					plugui.Action{Label: "继续手动短信", Path: loginResourcePath, Query: "action=sms&state=" + state},
				),
			)
		}
	}
	// 2. Attach to an already-saved credential, identified by auth file name
	//    or phone number. Existing 16 password-less files stay valid; this
	//    only adds a password to the one the operator named.
	cfg := settings()
	entry, found := selectAccount(h, request)
	if !found && validPhone(phone) {
		for _, candidate := range loomyAccounts(h) {
			cred, errCred := credentialOf(h, candidate)
			if errCred != nil {
				continue
			}
			if normalizePhone(cred.Phone) == normalizePhone(phone) {
				entry, found = candidate, true
				break
			}
		}
	}
	if !found {
		if wantsJSON(request) {
			return jsonManagementResponse(http.StatusNotFound, map[string]any{"ok": false, "error": "找不到对应的已保存账号"})
		}
		return renderPasswordSaveForm(request, "找不到对应的已保存账号，请先完成登录，或在登录会话里附上密码。", "danger")
	}
	credential, errCred := credentialOf(h, entry)
	if errCred != nil {
		if wantsJSON(request) {
			return jsonManagementResponse(http.StatusBadRequest, map[string]any{"ok": false, "error": errCred.Error()})
		}
		return renderPasswordSaveForm(request, errCred.Error(), "danger")
	}
	credential.SetPassword(password)
	auth, errAuth := authDataFor(credential, entry.Name)
	if errAuth != nil {
		return renderPasswordSaveForm(request, errAuth.Error(), "danger")
	}
	if h != nil {
		saved, errSave := h.SaveAuth(auth.FileName, auth.StorageJSON)
		if errSave != nil {
			return renderPasswordSaveForm(request, "保存凭据失败", "danger")
		}
		if saved != nil {
			chmodCredentialFile(saved.Path)
		}
	}
	_ = cfg
	if wantsJSON(request) {
		return jsonManagementResponse(http.StatusOK, map[string]any{"ok": true, "attached": "credential", "auth_file": entry.Name, "has_password": true})
	}
	return pluguiPage("Loomy 保存续登密码",
		plugui.Notice("success", "续登密码已加密写入凭据。下次会话接近过期时会用它自动重登。"),
		plugui.Card("", plugui.Group(),
			plugui.Action{Label: "查看状态", Path: "/v0/resource/plugins/loomy-provider/status", Kind: "primary"},
		),
	)
}

func postedCredentials(request pluginapi.ManagementRequest) (phone, password, state string) {
	values := postedValues(request)
	phone = normalizePhone(firstNonEmpty(values.Get("phone"), request.Query.Get("phone")))
	password = values.Get("password")
	state = firstNonEmpty(values.Get("state"), request.Query.Get("state"))
	return phone, password, strings.TrimSpace(state)
}

func postedValues(request pluginapi.ManagementRequest) url.Values {
	values := url.Values{}
	if len(request.Body) > 0 {
		trimmed := strings.TrimSpace(string(request.Body))
		if strings.HasPrefix(trimmed, "{") {
			var body map[string]any
			if json.Unmarshal(request.Body, &body) == nil {
				for k, v := range body {
					if s, ok := v.(string); ok {
						values.Set(k, s)
					}
				}
			}
		} else {
			if parsed, errParse := url.ParseQuery(trimmed); errParse == nil {
				values = parsed
			}
		}
	}
	return values
}

func postedOrQuery(request pluginapi.ManagementRequest, key string) string {
	if v := postedValues(request).Get(key); v != "" {
		return v
	}
	return strings.TrimSpace(request.Query.Get(key))
}

func htmlEsc(s string) string {
	return template.HTMLEscapeString(s)
}

func passwordSaveQuery(session *loginSession, credential *Credential) string {
	values := []string{}
	if session != nil {
		if s := session.stateValue(); s != "" {
			values = append(values, "state="+s)
		}
	}
	if credential != nil {
		if p := normalizePhone(credential.Phone); p != "" {
			values = append(values, "phone="+p)
		}
	}
	return strings.Join(values, "&")
}
