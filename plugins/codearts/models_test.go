package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

// Case-only OAuth aliases are ignored by CPA (EqualFold), therefore CodeArts
// publishes the canonical public spelling itself and maps it back before the
// upstream call.
func TestPublicAndUpstreamModelID(t *testing.T) {
	if got := publicModelID("glm-5.3-flash"); got != "GLM-5.3-Flash" {
		t.Errorf("publicModelID = %q", got)
	}
	if got := upstreamModelID("GLM-5.3-Flash"); got != "glm-5.3-flash" {
		t.Errorf("upstreamModelID = %q", got)
	}
	info := modelInfoFor("glm-5.3-flash", "glm-5.3-flash")
	if info.ID != "GLM-5.3-Flash" || info.Name != "glm-5.3-flash" {
		t.Errorf("model info = %+v", info)
	}
}

// TestPublicModelNamesAreCanonicalAndReversed covers the id mapping in both
// directions.
//
// The reverse direction is load-bearing. Publishing `DeepSeek-V4.1-Flash` while
// sending the undated id reaches a gateway that, since 2026-11-02, only accepts
// `deepseek-v4.1-flash-1017` (the undated id returns
// InferHub.ModelArts.81003.401). Doing the rename in the plugin (rather than in
// the host's `oauth-model-alias`) is deliberate — that table cannot reliably hand
// an already-taken name to a second provider, measured 2026-10-01.
func TestPublicModelNamesAreCanonicalAndReversed(t *testing.T) {
	if got := publicModelID("deepseek-v4.1-flash"); got != "DeepSeek-V4.1-Flash" {
		t.Fatalf("publicModelID = %q, want the canonical name", got)
	}
	if got := publicModelID(deepseekV41FlashWire); got != deepseekV41FlashPublic {
		t.Fatalf("publicModelID(dated) = %q, want the canonical name", got)
	}
	// Case-insensitive, because the upstream id's casing has drifted before.
	if got := publicModelID("DeepSeek-V4.1-Flash"); got != "DeepSeek-V4.1-Flash" {
		t.Fatalf("publicModelID(canonical) = %q", got)
	}
	for _, spelling := range []string{
		"DeepSeek-V4.1-Flash",
		"deepseek-v4.1-flash",
		deepseekV41FlashWire,
		"DeepSeek-V4.1-Flash-1017",
	} {
		if got := upstreamModelID(spelling); got != deepseekV41FlashWire {
			t.Fatalf("upstreamModelID(%q) = %q, want %q", spelling, got, deepseekV41FlashWire)
		}
	}
	if got := publicModelID(BenefitModel); got != "GLM-5.3-Flash" {
		t.Fatalf("the benefit model lost its mapping: %q", got)
	}
	if got := upstreamModelID("GLM-5.3-Flash"); got != BenefitModel {
		t.Fatalf("the benefit model's reverse mapping broke: %q", got)
	}
	// An unknown id passes through untouched in both directions.
	if got := publicModelID("glm-5.2"); got != "glm-5.2" {
		t.Fatalf("unknown id rewritten to %q", got)
	}
	if got := upstreamModelID("GLM-5.2"); got != "GLM-5.2" {
		t.Fatalf("unknown public name rewritten to %q", got)
	}
}

// TestDeepSeekV41FlashRequestUsesTheDatedWireID pins the body that actually
// leaves the plugin. The host may pass the public name, the old undated id, or
// the dated id the catalogue lists; InferHub only accepts the last of those.
func TestDeepSeekV41FlashRequestUsesTheDatedWireID(t *testing.T) {
	payload := func(model string) []byte {
		return []byte(`{"model":"` + model + `","messages":[{"role":"user","content":"hi"}]}`)
	}
	for _, spelling := range []string{"DeepSeek-V4.1-Flash", "deepseek-v4.1-flash", deepseekV41FlashWire} {
		encoded, request, _, errPrepare := prepareRequestBody(payload(spelling), spelling, DefaultConfig(), "sess-v41")
		if errPrepare != nil {
			t.Fatalf("prepareRequestBody(%q): %v", spelling, errPrepare)
		}
		if request.Model != deepseekV41FlashWire {
			t.Fatalf("request model for %q = %q, want %q", spelling, request.Model, deepseekV41FlashWire)
		}
		var wire struct {
			Model string `json:"model"`
		}
		if errDecode := json.Unmarshal(encoded, &wire); errDecode != nil {
			t.Fatalf("decode wire body: %v", errDecode)
		}
		if wire.Model != deepseekV41FlashWire {
			t.Fatalf("wire model for %q = %q, want %q", spelling, wire.Model, deepseekV41FlashWire)
		}
	}

	// A payload-only request (no host model argument) takes the same path.
	encoded, request, _, errPrepare := prepareRequestBody(payload("DeepSeek-V4.1-Flash"), "", DefaultConfig(), "sess-v41")
	if errPrepare != nil {
		t.Fatalf("prepareRequestBody(payload only): %v", errPrepare)
	}
	if request.Model != deepseekV41FlashWire {
		t.Fatalf("payload-only model = %q, want %q", request.Model, deepseekV41FlashWire)
	}
	if !bytes.Contains(encoded, []byte(`"model":"`+deepseekV41FlashWire+`"`)) {
		t.Fatalf("wire body dropped the dated id: %s", encoded)
	}
}

// TestRecordModelKeepsDatedCatalogueIDs pins discovery. The dated V4.1 id is
// stored and published under the shared public name; another dated id is
// published as the catalogue wrote it; the legacy 0731 alias is still folded
// onto the undated id the endpoint accepts.
func TestRecordModelKeepsDatedCatalogueIDs(t *testing.T) {
	out := map[string]string{}
	recordModel(out, deepseekV41FlashWire, "DeepSeek V4.1 Flash")
	recordModel(out, "deepseek-v4.1-flash", "undated duplicate")
	recordModel(out, "deepseek-v4-pro-0815", "")
	recordModel(out, "deepseek-v4-flash-0731", "")

	if got := out[deepseekV41FlashWire]; got != "DeepSeek V4.1 Flash" {
		t.Fatalf("dated v4.1 entry = %q, catalogue %#v", got, out)
	}
	if _, ok := out["deepseek-v4.1-flash"]; ok {
		t.Fatalf("undated v4.1 id was stored beside the dated one: %#v", out)
	}
	if _, ok := out["deepseek-v4-pro-0815"]; !ok {
		t.Fatalf("an unrelated dated id was stripped: %#v", out)
	}
	if _, ok := out["deepseek-v4-flash-0731"]; ok {
		t.Fatalf("legacy dated id was kept: %#v", out)
	}
	if _, ok := out[legacyUndatedDeepseekV4Flash]; !ok {
		t.Fatalf("legacy alias was not rewritten: %#v", out)
	}

	info := modelInfoFor(deepseekV41FlashWire, out[deepseekV41FlashWire])
	if info.ID != deepseekV41FlashPublic {
		t.Fatalf("published id = %q, want %q", info.ID, deepseekV41FlashPublic)
	}
	if info.Name != deepseekV41FlashWire {
		t.Fatalf("native name = %q, want the dated wire id", info.Name)
	}
	dated := modelInfoFor("deepseek-v4-pro-0815", "deepseek-v4-pro-0815")
	if dated.ID != "deepseek-v4-pro-0815" || dated.Name != "deepseek-v4-pro-0815" {
		t.Fatalf("unrelated dated model was rewritten: %+v", dated)
	}
}
