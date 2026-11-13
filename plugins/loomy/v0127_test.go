package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/collegeming/cpa-jethub-plugins/internal/abiboot"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

const disabledEnvelope = `{"ok":false,"code":"100003","desc":"账号已停用"}`

func envelope100003(_ abiboot.HTTPDoRequest) (*pluginapi.HTTPResponse, error) {
	return httpResponse(200, disabledEnvelope), nil
}

func rejectPasswordLogin(t *testing.T, request abiboot.HTTPDoRequest) {
	t.Helper()
	if strings.Contains(request.URL, GetPuKeyPath) || strings.Contains(request.URL, ByPwdPath) {
		t.Fatal("100003 must not start a password login")
	}
}

func (f *fakeHost) savedJSON(name string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	if raw := f.saved[name]; raw != nil {
		out := make([]byte, len(raw))
		copy(out, raw)
		return out
	}
	return nil
}

func requirePlatformPark(t *testing.T, fake *fakeHost, fileName string) {
	t.Helper()
	if fake.saveWrites() < 1 {
		t.Fatal("100003 must persist a park via host.auth.save")
	}
	raw := fake.savedJSON(fileName)
	if len(raw) == 0 {
		t.Fatalf("no save for %s; saved %v", fileName, fake.savedNames())
	}
	var overlay map[string]any
	if err := json.Unmarshal(raw, &overlay); err != nil {
		t.Fatalf("decode park overlay: %v", err)
	}
	if overlay["disabled"] != true {
		t.Fatalf("disabled = %#v, want true", overlay["disabled"])
	}
	if overlay["disabled_by"] != "loomy:platform" {
		t.Fatalf("disabled_by = %#v, want loomy:platform", overlay["disabled_by"])
	}
	if overlay["platform_disabled"] != true {
		t.Fatalf("platform_disabled = %#v, want true", overlay["platform_disabled"])
	}
}

// TestOnboardingJSON100003ParksWithoutRelogin is the gap the 0.1.26 deploy
// observed: a read-only onboarding GET returned 403 for 100003 but left the
// credential enabled. Parking belongs on this path, not only on chat / refresh.
func TestOnboardingJSON100003ParksWithoutRelogin(t *testing.T) {
	fake := newFakeHost()
	fake.do = func(request abiboot.HTTPDoRequest) (*pluginapi.HTTPResponse, error) {
		rejectPasswordLogin(t, request)
		return envelope100003(request)
	}
	fake.install(t)
	withAccount(t, fake)

	response := callManagement(t, testHost(), jsonManagementRequest(http.MethodGet,
		"/v0/resource/plugins/loomy/onboarding", nil))
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 so CPA switches accounts; body=%s", response.StatusCode, response.Body)
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body, &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	errText, _ := body["error"].(string)
	if !strings.Contains(errText, "100003") || !strings.Contains(errText, "平台停用") {
		t.Fatalf("error = %q, want 100003 platform-disabled wording", errText)
	}
	if strings.Contains(errText, "请重新登录") {
		t.Fatal("100003 must not advise a re-login")
	}
	requirePlatformPark(t, fake, "loomy-13800138000.json")
}

// TestStatusPoints100003Parks covers the status page / ?refresh=1 points
// read, which uses collectQuotas.
func TestStatusPoints100003Parks(t *testing.T) {
	fake := newFakeHost()
	fake.do = func(request abiboot.HTTPDoRequest) (*pluginapi.HTTPResponse, error) {
		rejectPasswordLogin(t, request)
		return envelope100003(request)
	}
	fake.install(t)
	withAccount(t, fake)

	response := callManagement(t, testHost(), jsonManagementRequest(http.MethodGet,
		"/v0/resource/plugins/loomy/status", url.Values{"refresh": {"1"}}))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status page is still served; status = %d", response.StatusCode)
	}
	requirePlatformPark(t, fake, "loomy-13800138000.json")
}

// TestCheckinClaim100003Parks covers the daily-grant write path.
func TestCheckinClaim100003Parks(t *testing.T) {
	fake := newFakeHost()
	fake.do = func(request abiboot.HTTPDoRequest) (*pluginapi.HTTPResponse, error) {
		rejectPasswordLogin(t, request)
		return envelope100003(request)
	}
	fake.install(t)
	withAccount(t, fake)

	response := callManagement(t, testHost(), jsonManagementRequest(http.MethodGet,
		"/v0/resource/plugins/loomy/checkin", url.Values{"action": {"claim"}}))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("checkin JSON stays 200 with a failed body; status = %d body=%s", response.StatusCode, response.Body)
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body, &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "failed" {
		t.Fatalf("status = %#v, want failed", body["status"])
	}
	msg, _ := body["message"].(string)
	if !strings.Contains(msg, "100003") {
		t.Fatalf("message = %q, want 100003", msg)
	}
	requirePlatformPark(t, fake, "loomy-13800138000.json")
}

// TestStreamFrame100003ParksWithoutRelogin covers 100003 arriving as an SSE
// business frame (no raw JSON envelope), which performInfer does not see.
func TestStreamFrame100003ParksWithoutRelogin(t *testing.T) {
	fake := newFakeHost()
	fake.do = func(request abiboot.HTTPDoRequest) (*pluginapi.HTTPResponse, error) {
		rejectPasswordLogin(t, request)
		return httpResponse(200, "data: "+disabledEnvelope+"\n\n"), nil
	}
	fake.install(t)

	_, errExecute := handleExecutorExecuteStream(testHost(), executorPayload(t, sampleCredential(t), "MiniMax-M3", `{}`))
	if errExecute == nil {
		t.Fatal("SSE 100003 must fail the stream")
	}
	if statusOf(errExecute, 0) != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (not 502); err=%v", statusOf(errExecute, 0), errExecute)
	}
	if !isAccountDisabledErr(errExecute) {
		t.Fatalf("error = %v, want account_disabled", errExecute)
	}
	if strings.Contains(errExecute.Error(), "请重新登录") {
		t.Fatal("100003 must not advise a re-login")
	}
	requirePlatformPark(t, fake, "loomy-1")
}

func TestParkIfAccountDisabledIsNoopForOtherErrors(t *testing.T) {
	fake := newFakeHost()
	fake.install(t)
	err := transportError("x", "network")
	if got := parkIfAccountDisabled(testHost(), "loomy-1", sampleCredential(t), err); got != err {
		t.Fatalf("returned %v, want the same error", got)
	}
	if fake.saveWrites() != 0 {
		t.Fatal("non-100003 errors must not park")
	}
	if parkIfAccountDisabled(testHost(), "loomy-1", sampleCredential(t), nil) != nil {
		t.Fatal("nil must stay nil")
	}
}
