package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/collegeming/cpa-jethub-plugins/internal/abiboot"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

const (
	// deepseekV41FlashPublic is the spelling every other channel already
	// publishes. CodeArts has to publish that same name or the deployment
	// lists two entries for one model.
	deepseekV41FlashPublic = "DeepSeek-V4.1-Flash"
	// deepseekV41FlashWire is the id InferHub accepts for that model.
	// Verified live 2026-11-02 against
	// https://snap-access.cn-north-4.myhuaweicloud.com/api/v2/chat/completions:
	// `deepseek-v4.1-flash-1017` streams a normal reply, and the undated
	// `deepseek-v4.1-flash` returns InferHub.ModelArts.81003.401
	// ("The model does not exist or you do not have access to it").
	deepseekV41FlashWire = "deepseek-v4.1-flash-1017"

	// legacyDatedDeepseekV4Flash is the one dated spelling the chat endpoint
	// was measured to reject. The undated id is what that model is called.
	// A later dated id (the V4.1 Flash case above, or anything else the
	// catalogue lists) is the model's identity and must be kept.
	legacyDatedDeepseekV4Flash   = "deepseek-v4-flash-0731"
	legacyUndatedDeepseekV4Flash = "deepseek-v4-flash"
)

// defaultModelIDs is the fallback list used when model discovery is disabled or
// fails. It mirrors Jet-Hub's DEFAULT_MODELS, plus the dated V4.1 Flash id the
// gateway now requires (see deepseekV41FlashWire).
var defaultModelIDs = []string{
	"GLM-5.2",
	"GLM-5.1",
	"GLM-5",
	BenefitModel,
	"openpangu-2.0-flash",
	"openpangu-2.0-pro",
	"deepseek-v4-flash",
	"deepseek-v4-pro",
	deepseekV41FlashWire,
}

// contextWindows carries the known context lengths. Models absent from the map
// are advertised without a limit rather than with a guessed one.
var contextWindows = map[string]int64{
	"GLM-5.2":           202752,
	BenefitModel:        1048576,
	"deepseek-v4-flash": 1048576,
	"deepseek-v4-pro":   1048576,
}

// defaultMaxOutputTokens is the per-response cap advertised to the host.
const defaultMaxOutputTokens = 65536

// thinkingLevels are the two thinking levels declared for EVERY model
// (`llm-adapter.ts:841-849`).
//
// The gateway's only effective thinking control is the top-level `thinking.type`
// (see prepareRequestBody). `reasoning_effort` — all of low/high/none/minimal —
// and the nested `reasoning.effort` are accepted but completely inert: judged by
// the server-reported `reasoning_tokens`, which stayed inside baseline noise
// (`none` kept thinking too). `{type:'enabled'}` is equivalent to sending
// nothing, because the server defaults to thinking on. Upstream therefore
// refused to invent a low/high/max ladder — that would be three fake levels —
// and declares exactly on / off, in that display order.
//
// The levels are declared even though deepseek-v4 is the model family actually
// measured thinking: no endpoint publishes per-model capability, and the
// upstream adapter declares them for every model rather than guessing.
var thinkingLevels = []string{"on", "off"}

// modelCache memoises a discovered model list for a bounded time.
type modelCache struct {
	mu        sync.Mutex
	models    []pluginapi.ModelInfo
	fetchedAt time.Time
}

var discoveredModels modelCache

func (c *modelCache) get(ttl time.Duration) []pluginapi.ModelInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.models) == 0 || time.Since(c.fetchedAt) > ttl {
		return nil
	}
	return c.models
}

func (c *modelCache) put(models []pluginapi.ModelInfo) {
	if len(models) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.models = models
	c.fetchedAt = time.Now()
}

// peek returns the cached listing and its fetch time regardless of the TTL, so a
// refresh can compare the catalogue it is about to replace and the management
// page can report what was actually fetched.
func (c *modelCache) peek() ([]pluginapi.ModelInfo, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.models, c.fetchedAt
}

// reset drops the cached listing, which is what makes a refresh follow the same
// path a client request would: only the cache is removed.
func (c *modelCache) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.models = nil
	c.fetchedAt = time.Time{}
}

// staticModelInfos renders the fallback list.
func staticModelInfos() []pluginapi.ModelInfo {
	out := make([]pluginapi.ModelInfo, 0, len(defaultModelIDs))
	for _, id := range defaultModelIDs {
		out = append(out, modelInfoFor(id, ""))
	}
	return out
}

// publicModelID separates client-facing brand casing from the provider-native
// model id. CPA skips aliases whose name and alias are EqualFold, so the plugin
// must publish the canonical spelling itself.
// publicModelNames maps CodeArts' native ids onto the names this deployment
// publishes.
//
// Two families need it. `BenefitModel` is the benefit endpoint's own spelling,
// and both DeepSeek V4.1 Flash spellings the catalogue has used
// (`deepseek-v4.1-flash` and `deepseek-v4.1-flash-1017`) are the platform's
// form of a model every other channel already publishes as
// `DeepSeek-V4.1-Flash`. Leaving either lowercase, or publishing the dated id
// as its own name, put a second entry for one model in the list users pick from.
//
// The reverse direction is NOT this map. Two natives share one public name, and
// a range over the map would pick one of them at random. `upstreamModelID`
// sends the dated wire id, which is the one InferHub accepts.
//
// The mapping lives here rather than in the host's `oauth-model-alias` table
// because that table cannot reliably hand an ALREADY-TAKEN name to another
// provider — measured 2026-10-01, with the winner varying between reloads. A
// name the plugin publishes itself merges with the same name from other
// channels, the way `plugins/zcode/models.go` documents for `GLM-5.3-Flash`.
var publicModelNames = map[string]string{
	BenefitModel:          "GLM-5.3-Flash",
	"deepseek-v4.1-flash": deepseekV41FlashPublic,
	deepseekV41FlashWire:  deepseekV41FlashPublic,
}

// publicModelID returns the name this deployment publishes for a native id.
func publicModelID(id string) string {
	trimmed := strings.TrimSpace(id)
	for native, public := range publicModelNames {
		if strings.EqualFold(trimmed, native) {
			return public
		}
	}
	return trimmed
}

// deepseekV41FlashAlias reports whether id is any spelling of DeepSeek V4.1
// Flash this plugin accepts from a client or from the upstream catalogue.
func deepseekV41FlashAlias(id string) bool {
	switch strings.ToLower(strings.TrimSpace(id)) {
	case "deepseek-v4.1-flash", deepseekV41FlashWire, strings.ToLower(deepseekV41FlashPublic):
		return true
	default:
		return false
	}
}

// upstreamModelID maps a client or catalogue spelling onto the id InferHub
// accepts.
//
// `DeepSeek-V4.1-Flash`, the undated native id, and the dated id all go out as
// `deepseek-v4.1-flash-1017`. The undated id is what the plugin used to send,
// and it is what now returns 81003.401. A dated id that is not one of these
// aliases is returned unchanged: stripping it is what made a catalogue entry
// unreachable.
func upstreamModelID(id string) string {
	trimmed := normalizeModelID(id)
	if deepseekV41FlashAlias(trimmed) {
		return deepseekV41FlashWire
	}
	for native, public := range publicModelNames {
		// V4.1 Flash has two natives for one public name. The branch above is
		// the deterministic reverse; ranging the map would not be.
		if strings.EqualFold(public, deepseekV41FlashPublic) {
			continue
		}
		if strings.EqualFold(trimmed, public) {
			return native
		}
	}
	return trimmed
}

// publishedModels returns the catalogue this plugin would hand the host for the
// selected account, WITHOUT triggering a new discovery run.
//
// It exists for the status document: the hub's channel overview renders
// `model_count` (`plugins/hub/overview.go`, modelCountFacts), and reading the
// same source `model.for_auth` publishes keeps the two from disagreeing. Using
// the cache rather than calling discoverModels keeps a page load from issuing an
// extra upstream request every time it is refreshed.
func publishedModels() []pluginapi.ModelInfo {
	cfg := settings()
	ttl := time.Duration(cfg.ModelCacheTTLMS) * time.Millisecond
	if ttl <= 0 {
		ttl = 2 * time.Hour
	}
	if cached := discoveredModels.get(ttl); len(cached) > 0 {
		return cached
	}
	return staticModelInfos()
}

// modelInfoFor builds the host-facing model descriptor for one model id.
func modelInfoFor(id, displayName string) pluginapi.ModelInfo {
	name := strings.TrimSpace(displayName)
	if name == "" {
		name = id
	}
	publicID := publicModelID(id)
	if strings.EqualFold(name, id) {
		name = publicID
	}
	info := pluginapi.ModelInfo{
		ID:                         publicID,
		Object:                     "model",
		Created:                    time.Now().Unix(),
		OwnedBy:                    ProviderKey,
		Type:                       "chat",
		DisplayName:                name,
		Name:                       id,
		Description:                "Huawei Cloud CodeArts " + name,
		ContextLength:              contextWindows[id],
		MaxCompletionTokens:        defaultMaxOutputTokens,
		SupportedGenerationMethods: []string{"chat.completions"},
		SupportedInputModalities:   []string{"text"},
		SupportedOutputModalities:  []string{"text"},
	}
	// Declared for every model, mirroring the sibling adapters that get this
	// right (`cline/models.go:349-355`). Without it the host renders no thinking
	// selector at all, which is the defect this pins (`llm-adapter.ts:831-849`).
	info.Thinking = &pluginapi.ThinkingSupport{
		// The display order is load-bearing: `on` first, matching upstream.
		Levels: append([]string(nil), thinkingLevels...),
		// `off` is a real, measured level: `thinking:{type:'disabled'}` drove
		// `reasoning_tokens` to 0 in 3/3 runs while the answer text stayed
		// correct, so disabling reasoning is genuinely supported.
		ZeroAllowed: true,
	}
	if info.ContextLength == 0 {
		info.InputTokenLimit = 0
	} else {
		info.InputTokenLimit = info.ContextLength
	}
	info.OutputTokenLimit = defaultMaxOutputTokens
	return info
}

// normalizeModelID rewrites the one dated id the chat endpoint rejects
// (`deepseek-v4-flash-0731` -> `deepseek-v4-flash`).
//
// It used to strip every trailing 4-digit suffix. That hid
// `deepseek-v4.1-flash-1017`: the catalogue lists that dated id, the strip
// turned it into `deepseek-v4.1-flash`, and the gateway answers 81003.401 for
// the undated form. A dated id the catalogue lists is now kept. Only the
// legacy alias above is still rewritten.
func normalizeModelID(id string) string {
	trimmed := strings.TrimSpace(id)
	if strings.EqualFold(trimmed, legacyDatedDeepseekV4Flash) {
		return legacyUndatedDeepseekV4Flash
	}
	return trimmed
}

// catalogModelID is the key discovery stores for one upstream model_id.
//
// The legacy 0731 alias collapses onto the undated id the endpoint accepts.
// Both V4.1 Flash spellings collapse onto the dated wire id, so a catalogue
// that still lists the undated form and one that lists `-1017` publish a
// single `DeepSeek-V4.1-Flash` row. Every other dated id is stored as written.
func catalogModelID(raw string) string {
	id := normalizeModelID(raw)
	if deepseekV41FlashAlias(id) {
		return deepseekV41FlashWire
	}
	return id
}

// isVisionModel reports whether a model id denotes a vision variant, which the
// chat endpoint does not serve.
func isVisionModel(id string) bool {
	return strings.Contains(strings.ToUpper(id), "-VL-") || strings.HasSuffix(strings.ToUpper(id), "-VL")
}

// signedGET performs a Huawei-signed GET through the host transport. Headers in
// unsigned are attached after signing and therefore never verified.
func signedGET(h *abiboot.Host, credential *Credential, rawURL string, extraSigned, unsigned map[string]string) (*pluginapi.HTTPResponse, error) {
	parsed, errParse := url.Parse(rawURL)
	if errParse != nil {
		return nil, abiboot.Errorf("invalid_url", "parse %s: %v", rawURL, errParse)
	}
	wire := &http.Request{Method: http.MethodGet, URL: parsed, Header: http.Header{}}
	SignRequest(wire, nil, credential.AccessKeyID, credential.SecretAccessKey, credential.SecurityToken, time.Now(), extraSigned)
	for key, value := range unsigned {
		wire.Header[key] = []string{value}
	}
	return h.HTTPDo(abiboot.HTTPDoRequest{
		Method:  http.MethodGet,
		URL:     rawURL,
		Headers: wire.Header,
	})
}

// gatewayEnvelope is the benefit-model listing response.
type gatewayEnvelope struct {
	Result *struct {
		Models []struct {
			ModelID   string `json:"model_id"`
			ModelName string `json:"model_name"`
		} `json:"models"`
	} `json:"result"`
}

// builtinEnvelope is the regular-model listing response.
type builtinEnvelope struct {
	BuiltinModels []struct {
		ModelID   string `json:"model_id"`
		ModelName string `json:"model_name"`
	} `json:"builtinModels"`
}

// discoverModels merges both remote model listings. A failure in either source
// is tolerated as long as the other one answers.
func discoverModels(h *abiboot.Host, credential *Credential) []pluginapi.ModelInfo {
	found := map[string]string{}
	var firstErr error

	if err := fetchGatewayModels(h, credential, found); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := fetchBuiltinModels(h, credential, found); err != nil && firstErr == nil {
		firstErr = err
	}
	if len(found) == 0 {
		if firstErr != nil && h != nil {
			h.Log("warn", "CodeArts model discovery failed, using the built-in list", map[string]any{"error": firstErr.Error()})
		}
		return nil
	}

	// Preserve the fallback ordering first, then append newly discovered ids.
	infos := make([]pluginapi.ModelInfo, 0, len(found))
	seen := map[string]bool{}
	for _, id := range defaultModelIDs {
		if name, ok := found[id]; ok {
			infos = append(infos, modelInfoFor(id, name))
			seen[id] = true
		}
	}
	for id, name := range found {
		if seen[id] {
			continue
		}
		infos = append(infos, modelInfoFor(id, name))
	}
	return infos
}

// fetchGatewayModels reads the benefit-model listing.
func fetchGatewayModels(h *abiboot.Host, credential *Credential, out map[string]string) error {
	response, errDo := signedGET(h, credential, OpenGWGatewayConfigURL, nil, nil)
	if errDo != nil {
		return errDo
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return abiboot.Errorf("model_gateway_status", "gateway config returned HTTP %d", response.StatusCode)
	}
	var envelope gatewayEnvelope
	if errDecode := json.Unmarshal(response.Body, &envelope); errDecode != nil {
		return abiboot.Errorf("model_gateway_decode", "decode gateway config: %v", errDecode)
	}
	if envelope.Result == nil {
		return nil
	}
	for _, item := range envelope.Result.Models {
		recordModel(out, item.ModelID, item.ModelName)
	}
	return nil
}

// fetchBuiltinModels reads the regular-model listing. It requires the unsigned
// Agent-Type / X-Language headers the gateway expects.
func fetchBuiltinModels(h *abiboot.Host, credential *Credential, out map[string]string) error {
	unsigned := UnsignedHeaders()
	response, errDo := signedGET(h, credential, SnapModelBuiltinURL, nil, unsigned)
	if errDo != nil {
		return errDo
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return abiboot.Errorf("model_builtin_status", "builtin model listing returned HTTP %d", response.StatusCode)
	}
	var envelope builtinEnvelope
	if errDecode := json.Unmarshal(response.Body, &envelope); errDecode != nil {
		return abiboot.Errorf("model_builtin_decode", "decode builtin model listing: %v", errDecode)
	}
	for _, item := range envelope.BuiltinModels {
		recordModel(out, item.ModelID, item.ModelName)
	}
	return nil
}

// recordModel normalises and filters one discovered model entry.
func recordModel(out map[string]string, rawID, rawName string) {
	id := catalogModelID(rawID)
	if id == "" || isVisionModel(id) {
		return
	}
	if _, exists := out[id]; exists {
		return
	}
	name := strings.TrimSpace(rawName)
	if name == "" {
		name = id
	}
	out[id] = name
}
