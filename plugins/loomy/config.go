package main

import (
	"strconv"
	"strings"

	"github.com/collegeming/cpa-jethub-plugins/internal/jethub/brandicons"
	"github.com/collegeming/cpa-jethub-plugins/plugins/loomy/pool"
	"gopkg.in/yaml.v3"
)

// Provider identity. One plugin instance owns exactly one provider key.
const (
	// ProviderKey is the stable provider identifier written into CPA auth files
	// and matched by the account pool (`loomy-adapter.ts:45`,
	// `loomy-product.ts:89`).
	ProviderKey = "loomy"
	// legacyProviderKey is the `type` value found in existing auth files that
	// were stamped with the plugin file name instead of ProviderKey. Such
	// files are still ours: they are accepted on parse and list, and
	// ParseCredential rewrites the field so the next save converges.
	legacyProviderKey = "loomy-provider"
	// DisplayName is the human-readable name shown by management clients
	// (`loomy-product.ts:90`).
	DisplayName = "Loomy (讯飞)"
	// Version is the plugin release version.
	Version = "0.1.27"
	// Author identifies the plugin author organization.
	Author = "cpa-jethub"
	// Repository is the public source location of this plugin.
	Repository = "https://github.com/collegeming/cpa-jethub-plugins"
	// Logo stays empty: the Loomy desktop client publishes no favicon, and an
	// invented URL would render as a broken image in the manager.
	// The icon the Loomy site itself links. An empty logo renders nothing in
	// the panel, which is what every plugin looked like before this was set.
	Logo = brandicons.Loomy
)

// Hosts and paths. Both are PRODUCTION addresses and the source explicitly
// forbids switching to a test environment (`README.md:1386`).
const (
	// APIBase serves models, points, onboarding and chat completions
	// (`loomy.ts:30`).
	APIBase = "https://loomyad.xunfei.cn/api/v1"

	// ModelsPath is the catalogue listing (`index.ts:463-481`).
	ModelsPath = "/models"
	// ChatCompletionsPath is the OpenAI-compatible streaming endpoint
	// (`loomy-adapter.ts:331-337`).
	ChatCompletionsPath = "/chat/completions"
	// PointsRecordsPath is the read-only balance endpoint (`loomy-credits.ts:128-132`).
	PointsRecordsPath = "/points/records"
	// PointsFirstLoginPath is the WRITE endpoint that initialises the daily pool
	// (`loomy-credits.ts:213-215`). Never call it from a read path.
	PointsFirstLoginPath = "/points/first-login"
	// OnboardingTasksPath lists the one-off task state (`loomy-onboarding.ts:167-169`).
	OnboardingTasksPath = "/onboarding/tasks"
	// OnboardingCompletePath completes one task (`loomy-onboarding.ts:193-195`).
	OnboardingCompletePath = "/onboarding/tasks/complete"

	// SendMsgCodePath requests an SMS code (`loomy-oauth.ts:13`).
	SendMsgCodePath = "/login/phone/sendMsgCode"
	// CheckCodePath exchanges the SMS code for a session (`loomy-oauth.ts:14`).
	CheckCodePath = "/login/phone/checkCode"

	// BindAuthPath exchanges the WeChat `code` for a binding context
	// (`loomy-oauth.ts:214-242`). The WeChat code is SINGLE-USE; every later step
	// uses the `rcode` this call returns.
	BindAuthPath = "/login/thirdAccount/bind/auth"
	// BindSendMsgPath sends the SMS code that binds a phone to the WeChat
	// account (`loomy-oauth.ts:249-267`).
	BindSendMsgPath = "/login/thirdAccount/bind/sendMsg"
	// BindCheckCodePath submits that code and completes the login
	// (`loomy-oauth.ts:274-295`).
	BindCheckCodePath = "/login/thirdAccount/bind/checkCode"
	// BindSkipPath is the `bind === 1` shortcut: the account already has a
	// phone, so 讯飞 hands out a session without one
	// (`loomy-oauth.ts:303-318`).
	BindSkipPath = "/login/thirdAccount/bind/skip"
)

// iFlytek CAccount client envelope constants, sent in the `base` object of every
// account request (`loomy-oauth.ts:55-71`).
const (
	// AccountAppID is `base.appid` (`loomy-product.ts:96`, `loomy-oauth.ts:61`).
	AccountAppID = "GM3LOOMY"
	// AccountModelID is `base.modelid` (`loomy-oauth.ts:62`).
	AccountModelID = "Web"
	// AccountClientVersion is `base.version` (`loomy-oauth.ts:63`).
	AccountClientVersion = "1.0.0"
	// AccountDeviceID is `base.devid` (`loomy-oauth.ts:64`).
	AccountDeviceID = "web"
	// AccountUA is `base.ua`. It is hard-coded to macOS even on Windows and must
	// NOT be "fixed": the Windows client sends the same value
	// (`loomy-oauth.ts:65-66`, trap #25).
	AccountUA = "Loomy|Desktop|Electron|macOS"
	// DefaultLoomyVersion is the official desktop `loomy-version` header
	// (Loomy2api-CPAMC upstream.go, confirmed 0.9.39 as of 2026-11-11).
	DefaultLoomyVersion = "0.9.39"
)

// Timeouts and lifetimes, each the value the TypeScript source uses.
const (
	// RequestTimeoutMS is the business/account request timeout,
	// `LOOMY_REQUEST_TIMEOUT_MS` (`loomy.ts:45`).
	RequestTimeoutMS = 60_000
	// ModelsTimeoutMS is the `/models` fetch timeout (`index.ts:477`).
	ModelsTimeoutMS = 30_000
	// SMSCodeTTLSeconds is the SMS validity DECLARED to the server
	// (`loomy-oauth.ts:30,139`). The server does not echo it back.
	SMSCodeTTLSeconds = 300
	// SessionTTLSeconds is the session lifetime DECLARED to the server
	// (`loomy-oauth.ts:39`, `README.md:1397`). The response carries no expiry, so
	// `expires_at` is computed locally from this value
	// (`loomy-auth.ts:272`).
	SessionTTLSeconds = 1_209_600
	// LoginTimeoutMS bounds one interactive login session. The SMS path has no
	// documented timeout in the source; the WeChat flow's whole-login budget
	// (`LOOMY_WECHAT_LOGIN_TIMEOUT_MS`, `loomy-wechat-login.ts:70`) is reused so a
	// half-finished session cannot sit in memory forever.
	LoginTimeoutMS = 300_000
	// ModelCacheTTLMS bounds how long a discovered catalogue is reused.
	ModelCacheTTLMS = 2 * 60 * 60 * 1000
	// CredentialHealthIntervalMS is the credential probe cadence the reference
	// uses (every 30 min, `index.ts:490`). Surfaced as metadata only; the host
	// owns the schedule.
	CredentialHealthIntervalMS = 30 * 60 * 1000
)

// Config is the per-instance plugin configuration, decoded from the
// `config_yaml` subtree delivered with plugin.register / plugin.reconfigure.
type Config struct {
	Enabled  bool
	Priority int

	// Phone is the default mobile number the manual SMS login page offers. It is
	// only a convenience: the primary login path is auto SMS (接码), which draws
	// a number itself, and the manual SMS page can collect one with digit links
	// (the resource mount is GET-only, so there is no input field to type into).
	Phone string

	// AccountAK / AccountSK optionally override the client-distributed signing
	// credentials. Leave empty to use the embedded pair.
	AccountAK string
	AccountSK string

	// SMSCodeTTLSeconds / SessionTTLSeconds are declared to the account host and
	// the latter also defines the locally computed `expires_at`.
	SMSCodeTTLSeconds int
	SessionTTLSeconds int
	// LoginTimeoutMS bounds one interactive login session.
	LoginTimeoutMS int
	// RequestTimeoutMS bounds a single buffered upstream call.
	RequestTimeoutMS int

	// DiscoverModels enables the live `GET /models` catalogue. It is off by
	// default so `model.*` never touches the network when no account exists
	// (`loomy-adapter.ts:198-200`).
	DiscoverModels bool
	// ModelPrefix 是否把账号 ID 作为模型前缀暴露（<账号>/<模型>）。关闭后模型列表只显示模型本身的名字。
	ModelPrefix bool
	// ModelPrefixName 所有账号共用的模型前缀（默认 "loomy"，即 loomy/<模型>）。设为空字符串则回到按账号 ID 前 8 位做前缀。
	ModelPrefixName string
	// ModelCacheTTLMS bounds the discovered catalogue lifetime.
	ModelCacheTTLMS int
	// ModelRefreshMS is how often the catalogue is refetched in the background,
	// so the cache does not depend on a client request to stay fresh. 0 disables
	// the background refresh, which is the default: it costs one vendor round
	// trip per interval, and the page's 刷新目录 button covers the manual case.
	ModelRefreshMS int
	// PointsCacheTTLMS bounds how long one account's point snapshot is reused.
	// A status-page load or a quota.fetch inside the TTL costs zero upstream
	// calls; the daily-grant claim invalidates the account's entry on success.
	// 0 disables the cache and every read hits upstream.
	PointsCacheTTLMS int

	// UserAgent is the HTTP User-Agent and the login-envelope `ua` sent to
	// the gateway and the account host. Empty uses AccountUA.
	UserAgent string
	// LoomyVersion is the `loomy-version` header. Empty uses DefaultLoomyVersion.
	LoomyVersion string
	// ProxyURL is a process-wide HTTP(S)/SOCKS5 proxy used when a credential
	// does not carry its own `proxy_url`.
	ProxyURL string
	// CredentialKeyFile is the 0600 AES key used to encrypt stored passwords.
	// Empty uses `$XDG_CONFIG_HOME/loomy-provider/credential.key`.
	CredentialKeyFile string
	// CheckinWindowStart / CheckinWindowEnd bound the daily auto-check-in
	// window in Asia/Shanghai (default 00:10–06:00).
	CheckinWindowStart string
	CheckinWindowEnd   string
	// RiskPauseSec is how long the risk circuit breaker holds requests after
	// two accounts are 403'd inside 10 minutes. 0 disables the breaker.
	// A negative value is treated as 0. DefaultConfig fills 1800; a user
	// who writes `risk_pause_sec: 0` disables it.
	RiskPauseSec int
	// riskPauseSet is true when risk_pause_sec was present in the YAML, so
	// a literal 0 can disable the breaker without colliding with "unset".
	riskPauseSet bool

	// Pool holds the account-pool scanner settings, decoded from the `pool_*`
	// keys of the same YAML block.
	Pool pool.Config

	// SMSToken / SMSKeyword / SMSAPIBase / SMSWaitMS configure d1jiema auto
	// SMS login (接码). Same platform as autoclaw / codeartsreg.
	SMSToken   string
	SMSKeyword string
	SMSAPIBase string
	SMSWaitMS  int
}

// DefaultConfig returns the settings used when the user provides nothing.
func DefaultConfig() Config {
	return Config{
		Enabled:            true,
		ModelPrefix:        true,
		ModelPrefixName:    "loomy",
		SMSCodeTTLSeconds:  SMSCodeTTLSeconds,
		SessionTTLSeconds:  SessionTTLSeconds,
		LoginTimeoutMS:     LoginTimeoutMS,
		RequestTimeoutMS:   RequestTimeoutMS,
		ModelCacheTTLMS:    ModelCacheTTLMS,
		ModelRefreshMS:     0,
		PointsCacheTTLMS:   30_000,
		UserAgent:          AccountUA,
		LoomyVersion:       DefaultLoomyVersion,
		CheckinWindowStart: pool.DefaultCheckinWindowStart,
		CheckinWindowEnd:   pool.DefaultCheckinWindowEnd,
		RiskPauseSec:       defaultRiskPauseSec,
		Pool:               pool.DefaultConfig(),
	}
}

// ConfigFromYAML decodes the settings the host supplies for this instance.
//
// The document is first decoded into a generic mapping and every key is then
// coerced individually. Three properties follow, all of which matter in practice:
//
//   - block AND flow style are both accepted, because the host hands the instance
//     subtree back in whichever style the user wrote it. A block-only line
//     scanner silently ignores `{discover_models: true, phone: 13800138000}` and
//     falls back to every default without reporting anything;
//   - values YAML 1.2 sees as strings but a user reasonably writes as booleans
//     (`yes`/`no`/`on`/`off`, or a quoted number) still work. yaml.v3 is YAML 1.2,
//     so a typed decode into `bool` would fail on `no` and discard the whole
//     document;
//   - one unusable value costs only its own default instead of the whole file.
func ConfigFromYAML(document []byte) Config {
	cfg := DefaultConfig()
	if len(document) == 0 {
		return cfg
	}
	var raw map[string]any
	if errUnmarshal := yaml.Unmarshal(document, &raw); errUnmarshal != nil {
		return DefaultConfig()
	}

	cfg.Enabled = coerceBool(raw["enabled"], cfg.Enabled)
	cfg.Priority = coerceInt(raw["priority"], cfg.Priority)
	cfg.Phone = coercePhone(raw["phone"], cfg.Phone)
	cfg.AccountAK = coerceString(raw["account_ak"], cfg.AccountAK)
	cfg.AccountSK = coerceString(raw["account_sk"], cfg.AccountSK)
	cfg.SMSCodeTTLSeconds = coerceInt(raw["sms_code_ttl_seconds"], cfg.SMSCodeTTLSeconds)
	cfg.SessionTTLSeconds = coerceInt(raw["session_ttl_seconds"], cfg.SessionTTLSeconds)
	cfg.LoginTimeoutMS = coerceInt(raw["login_timeout_ms"], cfg.LoginTimeoutMS)
	cfg.RequestTimeoutMS = coerceInt(raw["request_timeout_ms"], cfg.RequestTimeoutMS)
	cfg.DiscoverModels = coerceBool(raw["discover_models"], cfg.DiscoverModels)
	cfg.ModelPrefix = coerceBool(raw["model_prefix"], cfg.ModelPrefix)
	if v, ok := raw["model_prefix_name"].(string); ok {
		cfg.ModelPrefixName = strings.TrimSpace(v)
	}
	cfg.ModelCacheTTLMS = coerceInt(raw["model_cache_ttl_ms"], cfg.ModelCacheTTLMS)
	cfg.ModelRefreshMS = coerceInt(raw["model_refresh_ms"], cfg.ModelRefreshMS)
	cfg.PointsCacheTTLMS = coerceInt(raw["points_cache_ttl_ms"], cfg.PointsCacheTTLMS)
	cfg.SMSToken = coerceString(raw["sms_token"], cfg.SMSToken)
	cfg.SMSKeyword = coerceString(raw["sms_keyword"], cfg.SMSKeyword)
	cfg.SMSAPIBase = coerceString(raw["sms_api_base"], cfg.SMSAPIBase)
	cfg.SMSWaitMS = coerceInt(raw["sms_wait_ms"], cfg.SMSWaitMS)
	if cfg.SMSWaitMS == 0 {
		// also accept seconds form used by older aPipixia configs
		cfg.SMSWaitMS = coerceInt(raw["sms_wait_seconds"], 0) * 1000
	}
	cfg.UserAgent = coerceString(raw["user_agent"], cfg.UserAgent)
	cfg.LoomyVersion = coerceString(raw["loomy_version"], cfg.LoomyVersion)
	cfg.ProxyURL = coerceString(raw["proxy_url"], cfg.ProxyURL)
	cfg.CredentialKeyFile = coerceString(raw["credential_key_file"], cfg.CredentialKeyFile)
	cfg.CheckinWindowStart = coerceString(raw["checkin_window_start"], cfg.CheckinWindowStart)
	cfg.CheckinWindowEnd = coerceString(raw["checkin_window_end"], cfg.CheckinWindowEnd)
	if _, present := raw["risk_pause_sec"]; present {
		cfg.riskPauseSet = true
		cfg.RiskPauseSec = coerceInt(raw["risk_pause_sec"], 0)
	}
	cfg.Pool = pool.ConfigFromMap(raw, "pool_")
	// Unprefixed window keys win, but only when the operator actually wrote
	// them: otherwise a DefaultConfig value of "00:10" would clobber a
	// distinct pool_checkin_window_start.
	if _, present := raw["checkin_window_start"]; present {
		cfg.Pool.CheckinWindowStart = cfg.CheckinWindowStart
	}
	if _, present := raw["checkin_window_end"]; present {
		cfg.Pool.CheckinWindowEnd = cfg.CheckinWindowEnd
	}
	return cfg
}

// coercePhone accepts a phone number written as a number or a string. A YAML
// number loses nothing here because the number is stored as text everywhere else
// (the account host wants an 11-digit string).
func coercePhone(value any, fallback string) string {
	switch typed := value.(type) {
	case nil:
		return fallback
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		return coerceString(value, fallback)
	}
}

// coerceBool accepts a real boolean, a number, or the string spellings users
// write in configuration files.
func coerceBool(value any, fallback bool) bool {
	switch typed := value.(type) {
	case nil:
		return fallback
	case bool:
		return typed
	case int:
		return typed != 0
	case int64:
		return typed != 0
	case float64:
		return typed != 0
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "true", "yes", "on", "1":
			return true
		case "false", "no", "off", "0":
			return false
		}
		return fallback
	default:
		return fallback
	}
}

// coerceInt accepts a number or a numeric string, including a quoted one.
func coerceInt(value any, fallback int) int {
	switch typed := value.(type) {
	case nil:
		return fallback
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case string:
		parsed, errParse := strconv.Atoi(strings.TrimSpace(typed))
		if errParse != nil {
			return fallback
		}
		return parsed
	default:
		return fallback
	}
}

// coerceString returns a non-empty trimmed string, else the fallback.
func coerceString(value any, fallback string) string {
	if text, ok := value.(string); ok {
		if trimmed := strings.TrimSpace(text); trimmed != "" {
			return trimmed
		}
	}
	return fallback
}

// ConfigFields describes the settings the CPA management UI renders.
func ConfigFields() []configField {
	return []configField{
		{Name: "phone", Type: "string",
			Description: "短信登录页的默认手机号（11 位，如 13800138000），可留空。主路径是自动接码，一般不需要填；" +
				"手动短信备用路径可在登录页用数字链接输入，或用 ?phone= 覆盖"},
		{Name: "discover_models", Type: "boolean",
			Description: "是否用账号会话实时拉取 GET /models 目录（默认关闭）。关闭时只使用内置的 8 个兜底模型"},
		{Name: "model_prefix_name", Type: "string", Description: "所有账号共用的模型前缀，默认 loomy（模型名为 loomy/<模型>）；留空则按账号 ID 前 8 位做前缀"},
		{Name: "model_prefix", Type: "boolean", Description: "是否把账号 ID 作为模型前缀暴露（<账号>/<模型>）。关闭后模型列表只显示模型本身的名字"},
		{Name: "model_cache_ttl_ms", Type: "integer", Description: "实时模型目录的缓存时长，毫秒（默认 2 小时）"},
		{Name: "points_cache_ttl_ms", Type: "integer", Description: "单账号积分快照缓存时长，毫秒（默认 30000，0=关闭缓存每次实时查询；签到成功后自动失效）"},
		{Name: "model_refresh_ms", Type: "integer",
			Description: "后台自动刷新目录的间隔，毫秒（默认 0 = 关闭）。开启后每隔该时长重拉一次 GET /models；" +
				"只有在目录确实变化时才写凭据文件通知宿主重新注册（目录不变则不写，因此稳定期零写入）；" +
				"无论是否变化都可用状态页的「刷新目录」按钮手动刷新并强制通知宿主"},
		{Name: "sms_code_ttl_seconds", Type: "integer", Description: "向讯飞账号服务声明的短信验证码有效期，秒（默认 300）"},
		{Name: "session_ttl_seconds", Type: "integer",
			Description: "向讯飞账号服务声明的会话有效期，秒（默认 1209600 = 14 天）。服务端不回传过期时间，本地 expires_at 由该值推算"},
		{Name: "login_timeout_ms", Type: "integer", Description: "单次交互式登录会话的存活时长，毫秒（默认 5 分钟）"},
		{Name: "request_timeout_ms", Type: "integer", Description: "单次上游请求超时，毫秒（默认 60000）"},
		{Name: "account_ak", Type: "string",
			Description: "讯飞账号服务签名用的 accessKeyId。留空使用内置值（来自 Loomy 桌面客户端）；上游轮换后可在不改插件的情况下覆盖"},
		{Name: "account_sk", Type: "string",
			Description: "讯飞账号服务签名用的 accessKeySecret。留空使用内置值；仅在 account_ak 同时填写时有意义"},
		{Name: "sms_token", Type: "string",
			Description: "d1jiema 接码 token（与 autoclaw/codearts 可共用）。也可用环境变量 LOOMY_SMS_TOKEN / SMS_TOKEN"},
		{Name: "sms_keyword", Type: "string",
			Description: "接码短信抬头关键词（默认 讯飞）"},
		{Name: "sms_api_base", Type: "string",
			Description: "接码平台 API 地址（默认 https://api.d1jiema.com/zc/data.php）"},
		{Name: "sms_wait_ms", Type: "integer",
			Description: "自动接码等待短信的最长时间，毫秒（默认 90000）。也兼容 sms_wait_seconds"},
		{Name: "user_agent", Type: "string",
			Description: "发往网关和账号服务的 User-Agent，同时作为登录请求的 ua 字段（默认 Loomy|Desktop|Electron|macOS）"},
		{Name: "loomy_version", Type: "string",
			Description: "发往网关的 loomy-version 请求头（默认 0.9.39，与官方桌面端 / Loomy2api-CPAMC 一致）"},
		{Name: "proxy_url", Type: "string",
			Description: "全局 HTTP(S)/SOCKS5 代理，当某个凭据没有自己的 proxy_url 时使用"},
		{Name: "credential_key_file", Type: "string",
			Description: "用于加密本地密码的密钥文件路径（权限 0600）。留空则写到用户配置目录 loomy-provider/credential.key"},
		{Name: "checkin_window_start", Type: "string",
			Description: "自动签到窗口开始时间（默认 00:10，Asia/Shanghai）。每个账号在窗口内有一个按天稳定的随机时刻，避免 00:00 扎堆"},
		{Name: "checkin_window_end", Type: "string",
			Description: "自动签到窗口结束时间（默认 06:00，Asia/Shanghai）。窗口结束后仍未签到的账号会补签"},
		{Name: "risk_pause_sec", Type: "integer",
			Description: "风控熔断时长，秒（默认 1800）。10 分钟内有 2 个及以上账号被上游 403/TM.* 拒绝时暂停派发；0 关闭熔断。403 不会触发重新登录"},
	}
}

// configField mirrors pluginapi.ConfigField; the plugin package owns its own
// type so the ABI layer stays free of provider specifics.
type configField struct {
	Name        string
	Type        string
	EnumValues  []string
	Description string
}

// loginSessionTTL is the configured interactive-login lifetime.
func (c Config) loginSessionTTL() int {
	if c.LoginTimeoutMS > 0 {
		return c.LoginTimeoutMS
	}
	return LoginTimeoutMS
}

// smsCodeTTL is the SMS validity declared to the account host.
func (c Config) smsCodeTTL() int {
	if c.SMSCodeTTLSeconds > 0 {
		return c.SMSCodeTTLSeconds
	}
	return SMSCodeTTLSeconds
}

// sessionTTL is the session lifetime declared to the account host and used to
// derive the local `expires_at`.
func (c Config) sessionTTL() int {
	if c.SessionTTLSeconds > 0 {
		return c.SessionTTLSeconds
	}
	return SessionTTLSeconds
}

// requestTimeout is the configured single-request timeout.
func (c Config) requestTimeout() int {
	if c.RequestTimeoutMS > 0 {
		return c.RequestTimeoutMS
	}
	return RequestTimeoutMS
}

// modelCacheTTL is the configured discovered-catalogue lifetime.
func (c Config) modelCacheTTL() int {
	if c.ModelCacheTTLMS > 0 {
		return c.ModelCacheTTLMS
	}
	return ModelCacheTTLMS
}

// defaultPhone resolves the phone number a login link should use: the explicit
// query value wins, otherwise the configured default.
func (c Config) defaultPhone(override string) string {
	if trimmed := normalizePhone(override); trimmed != "" {
		return trimmed
	}
	return normalizePhone(c.Phone)
}

// clientUA is the official-client User-Agent sent on every gateway request
// and as the login envelope `ua`. The default must stay the macOS Electron
// value (trap #25); a setting only overrides it when non-empty.
func (c Config) clientUA() string {
	if trimmed := strings.TrimSpace(c.UserAgent); trimmed != "" {
		return trimmed
	}
	return AccountUA
}

// loomyVersion is the official-client `loomy-version` header.
func (c Config) loomyVersion() string {
	if trimmed := strings.TrimSpace(c.LoomyVersion); trimmed != "" {
		return trimmed
	}
	return DefaultLoomyVersion
}

// riskPauseSeconds is the circuit-breaker hold. 0 disables it. The default
// is 1800 when the field was left unset.
func (c Config) riskPauseSeconds() int {
	if c.riskPauseSet {
		if c.RiskPauseSec < 0 {
			return 0
		}
		return c.RiskPauseSec
	}
	if c.RiskPauseSec > 0 {
		return c.RiskPauseSec
	}
	return defaultRiskPauseSec
}
