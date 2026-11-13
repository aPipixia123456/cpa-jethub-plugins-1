package main

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestPasswordPagesAreOnManagementRoutes(t *testing.T) {
	fake := newFakeHost()
	fake.install(t)

	get := callManagement(t, testHost(), managementRequest(http.MethodGet, "/v0/management/loomy/pwdlogin", nil, nil))
	if get.StatusCode != 200 {
		t.Fatalf("GET pwdlogin status = %d", get.StatusCode)
	}
	body := string(get.Body)
	if !strings.Contains(strings.ToLower(body), "<form") {
		t.Fatal("the management password page must contain a form (POST is allowed here)")
	}
	if !strings.Contains(body, passwordLimitNote[:20]) {
		t.Fatal("the page must explain that the upstream has no set-password API")
	}
	if strings.Contains(strings.ToLower(body), "type=\"password\"") == false && !strings.Contains(body, `type="password"`) {
		t.Fatal("the form must have a password field")
	}

	save := callManagement(t, testHost(), managementRequest(http.MethodGet, "/v0/management/loomy/pwdsave", nil, nil))
	if save.StatusCode != 200 || !strings.Contains(strings.ToLower(string(save.Body)), "<form") {
		t.Fatalf("GET pwdsave status = %d, want a form", save.StatusCode)
	}
}

func TestPasswordLoginJSONRequiresFields(t *testing.T) {
	fake := newFakeHost()
	fake.install(t)
	req := managementRequest(http.MethodPost, "/v0/management/loomy/pwdlogin", nil, []byte(`{"phone":"13800138000"}`))
	req.Headers.Set("Accept", "application/json")
	req.Headers.Set("Content-Type", "application/json")
	resp := callManagement(t, testHost(), req)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if strings.Contains(string(resp.Body), "13800138000") && strings.Contains(strings.ToLower(string(resp.Body)), "password") && strings.Contains(string(resp.Body), `"password":"`) {
		t.Fatal("the error body must not echo a password")
	}
}

func TestPasswordSaveAttachesToSession(t *testing.T) {
	fake := newFakeHost()
	fake.install(t)
	session := startLoginSession(DefaultConfig(), "")
	body := url.Values{"password": {"attach-me"}, "state": {session.stateValue()}}.Encode()
	req := managementRequest(http.MethodPost, "/v0/management/loomy/pwdsave", nil, []byte(body))
	req.Headers = http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Accept": {"application/json"}}
	resp := callManagement(t, testHost(), req)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, resp.Body)
	}
	if session.passwordValue() != "attach-me" {
		t.Fatal("the session did not remember the submitted password")
	}
	if strings.Contains(string(resp.Body), "attach-me") {
		t.Fatal("the response must not echo the password")
	}
}

func TestResourceLoginPageHasNoPasswordForm(t *testing.T) {
	fake := newFakeHost()
	fake.install(t)
	page := renderPage(t, testHost(), "/login", url.Values{"action": {"sms"}})
	if strings.Contains(strings.ToLower(page), "<form") {
		t.Fatal("the resource login page must not contain a form")
	}
	if !strings.Contains(page, "pwdlogin") && !strings.Contains(page, passwordLoginPath) {
		t.Fatal("the login page must link to the management password-login route")
	}
}
