package pool

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/collegeming/cpa-jethub-plugins/internal/abiboot"
	"github.com/collegeming/cpa-jethub-plugins/internal/jethub/plugui"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// poolPage serves the resource route: HTML by default, JSON on ?format=json,
// and the action query strings for the operator buttons.
func poolPage(h *abiboot.Host, request pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	cfg := settings()

	switch strings.ToLower(strings.TrimSpace(request.Query.Get("action"))) {
	case "scan":
		outcome := runScan(h, cfg, "manual")
		if wantsJSON(request) {
			return jsonManagementResponse(http.StatusOK, outcome)
		}
		return renderPoolPage(h, cfg, &outcome)
	case "enable", "disable":
		return accountAction(h, cfg, request)
	}
	if wantsJSON(request) {
		return poolJSON(h, cfg)
	}
	return renderPoolPage(h, cfg, lastScanOutcome())
}

// accountAction applies the page's per-account buttons. A manual disable is
// marked `loomypool:manual` so the auto-enable sweep never resurrects it; a
// manual enable clears whatever marker is there, including a manual one.
func accountAction(h *abiboot.Host, cfg Config, request pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	name := strings.TrimSpace(request.Query.Get("name"))
	action := strings.ToLower(strings.TrimSpace(request.Query.Get("action")))
	if name == "" {
		return jsonManagementResponse(http.StatusBadRequest, map[string]any{"error": "name is required"})
	}
	entry, found := findAuthEntry(h, name)
	if !found {
		return jsonManagementResponse(http.StatusNotFound, map[string]any{"error": "凭据不存在：" + name})
	}
	var err error
	if action == "enable" {
		err = enableAccount(h, entry)
	} else {
		err = writeDisabled(h, entry.Name, true, disabledByManual)
	}
	if err != nil {
		if wantsJSON(request) {
			return jsonManagementResponse(http.StatusInternalServerError, map[string]any{"error": err.Error()})
		}
		return plugui.HTML(DisplayName, plugui.Card("操作失败", plugui.Notice("danger", err.Error()),
			plugui.Action{Label: "返回", Path: "pool"}))
	}
	h.Log("info", fmt.Sprintf("Loomy 账号 %s 由页面操作%s", name, map[string]string{"enable": "启用", "disable": "停用"}[action]),
		map[string]any{"auth": name, "action": action})
	if wantsJSON(request) {
		return jsonManagementResponse(http.StatusOK, map[string]any{"ok": true, "name": name, "action": action})
	}
	return renderPoolPage(h, cfg, lastScanOutcome())
}

// findAuthEntry resolves a credential file name to its host entry.
func findAuthEntry(h *abiboot.Host, name string) (pluginapi.HostAuthFileEntry, bool) {
	entries, errList := h.ListAuth()
	if errList != nil {
		return pluginapi.HostAuthFileEntry{}, false
	}
	for _, entry := range entries {
		if entry.Name == name && isLoomyEntry(entry) {
			return entry, true
		}
	}
	return pluginapi.HostAuthFileEntry{}, false
}

// poolJSON is the machine-readable pool document: the last scan plus the
// live account list and the scanner's effective configuration.
func poolJSON(h *abiboot.Host, cfg Config) pluginapi.ManagementResponse {
	outcome := lastScanOutcome()
	body := map[string]any{
		"config": map[string]any{
			"enabled":          cfg.Enabled,
			"scan_interval_ms": cfg.ScanIntervalMS,
			"min_remaining":    cfg.MinRemaining,
			"auto_disable":     cfg.AutoDisable,
			"auto_enable":      cfg.AutoEnable,
			"auto_checkin":     cfg.AutoCheckin,
		},
		"accounts":  liveAccountRows(h, outcome),
		"last_scan": outcome,
	}
	return jsonManagementResponse(http.StatusOK, body)
}

// liveAccountRows builds one row per loomy credential the host reports right
// now, then overlays whatever the remembered sweep measured for each account.
// A page load never calls upstream: rows carry name/label/status/disabled
// from the auth file and leave the measured columns empty, so the full roster
// is always visible.
func liveAccountRows(h *abiboot.Host, outcome *scanOutcome) []accountReport {
	entries, err := h.ListAuth()
	if err != nil {
		return nil
	}
	scanned := map[string]accountReport{}
	if outcome != nil {
		for _, account := range outcome.Accounts {
			scanned[account.Name] = account
		}
	}
	var rows []accountReport
	for _, entry := range entries {
		if !isLoomyEntry(entry) {
			continue
		}
		row := accountReport{
			Name:      entry.Name,
			AuthIndex: entry.AuthIndex,
			Label:     firstNonEmpty(entry.Label, entry.Email, entry.Account),
			Status:    statusOf(entry),
			Disabled:  entry.Disabled,
		}
		if prev, found := scanned[entry.Name]; found {
			row.Available, row.Balance, row.DailyBalance = prev.Available, prev.Balance, prev.DailyBalance
			row.Checkin, row.CheckinResult = prev.Checkin, prev.CheckinResult
			row.Action, row.Detail = prev.Action, prev.Detail
			if row.Label == "" {
				row.Label = prev.Label
			}
		} else if outcome != nil {
			row.Detail = "未在上次巡检中"
		}
		rows = append(rows, row)
	}
	return rows
}

// renderPoolPage renders the operator page: configuration, last sweep result,
// and a per-account table built from the remembered scan (the page never
// triggers a sweep by itself — a plain page load is read-only).
func renderPoolPage(h *abiboot.Host, cfg Config, outcome *scanOutcome) pluginapi.ManagementResponse {
	writeGuard := cfg.Enabled && (cfg.AutoDisable || cfg.AutoEnable)
	guardText := "开启"
	if !cfg.Enabled {
		guardText = "enabled=false：巡检只读不写"
	} else if !writeGuard {
		guardText = "auto_disable/auto_enable 均已关闭：巡检只读不写"
	}
	interval := time.Duration(cfg.ScanIntervalMS) * time.Millisecond
	intervalText := "已关闭（scan_interval_ms = 0）"
	if cfg.ScanIntervalMS > 0 {
		intervalText = "每 " + interval.String()
	}

	configCard := plugui.Card("巡检配置", plugui.Group(
		plugui.Fields(
			plugui.Field{Label: "写开关", Value: guardText},
			plugui.Field{Label: "自动巡检", Value: intervalText},
			plugui.Field{Label: "积分下限", Value: fmt.Sprintf("available ≤ %g 判定耗尽", cfg.MinRemaining)},
			plugui.Field{Label: "会话失效", Value: "检测到 100002 即停用（无 refresh 通道，需重新登录）"},
			plugui.Field{Label: "自动签到", Value: map[bool]string{true: "开启（领取到积分可同轮复活停用账号）", false: "关闭"}[cfg.AutoCheckin]},
		),
	), plugui.Action{Label: "立即巡检", Path: "pool", Query: "action=scan", Kind: "primary"},
		plugui.Action{Label: "返回状态", Path: "status"})

	var fragments []template.HTML
	fragments = append(fragments, configCard)

	if outcome == nil {
		fragments = append(fragments, plugui.Card("巡检结果", plugui.Notice("info", "尚未巡检。点「立即巡检」跑第一轮，或等自动巡检到点。")))
	} else {
		summaryTone := "success"
		summary := fmt.Sprintf("%s 完成：停用 %d 个，恢复 %d 个，共 %d 个账号",
			outcome.StartedAt.Local().Format("15:04:05"), outcome.DisabledNow, outcome.EnabledNow, len(outcome.Accounts))
		if outcome.Error != "" {
			summaryTone = "danger"
			summary = outcome.Error
		} else if outcome.DisabledNow > 0 {
			summaryTone = "warning"
		}
		fragments = append(fragments, plugui.Card("巡检结果", plugui.Group(
			plugui.Notice(summaryTone, summary),
			plugui.Fields(plugui.Field{Label: "触发方式", Value: outcome.Reason},
				plugui.Field{Label: "耗时", Value: fmt.Sprintf("%d ms", outcome.DurationMS)}),
		)))
	}

	// The table always renders the live roster (a page load is read-only and
	// never triggers a sweep): accounts get their measured points/checkin
	// columns from the remembered scan where it covered them, and show 未知/—
	// until the first sweep reaches them.
	accounts := liveAccountRows(h, outcome)
	if len(accounts) == 0 {
		fragments = append(fragments, plugui.Card("账号", plugui.Notice("info", "没有 loomy 类型的凭据。")))
		return plugui.HTMLWide(DisplayName, fragments...)
	}
	rows := make([][]template.HTML, 0, len(accounts))
	parked := 0
	for _, account := range accounts {
		if account.Disabled {
			parked++
		}
		rows = append(rows, poolRow(account))
	}
	parkedTone := ""
	if parked > 0 {
		parkedTone = "warning"
	}
	fragments = append(fragments, plugui.Card("账号", plugui.Group(
		plugui.Stats(
			plugui.Stat{Label: "账号", Value: strconv.Itoa(len(accounts))},
			plugui.Stat{Label: "在用", Value: strconv.Itoa(len(accounts) - parked), Tone: "success"},
			plugui.Stat{Label: "已停用", Value: strconv.Itoa(parked), Tone: parkedTone},
		),
		plugui.Table([]plugui.Column{
			{Label: "账号"},
			{Label: "可用", Numeric: true},
			{Label: "永久", Numeric: true},
			{Label: "每日", Numeric: true},
			{Label: "签到"},
			{Label: "状态"},
			{Label: "本次动作"},
			{Label: "操作"},
		}, rows),
	)))
	return plugui.HTMLWide(DisplayName, fragments...)
}

// poolRow renders one account's cells in the column order of renderPoolPage.
func poolRow(account accountReport) []template.HTML {
	name := template.HTML(`<strong>` + template.HTMLEscapeString(account.Name) + `</strong>`)
	if account.Label != "" {
		name += template.HTML(`<span class="sub">` + template.HTMLEscapeString(account.Label) + `</span>`)
	}
	checkin := account.Checkin
	if account.CheckinResult != "" {
		if checkin != "" {
			checkin = account.CheckinResult + "（" + checkin + "）"
		} else {
			checkin = account.CheckinResult
		}
	}
	if checkin == "" {
		checkin = "—"
	}
	outcome := template.HTML(template.HTMLEscapeString(actionText(account.Action)))
	if account.Detail != "" {
		outcome += template.HTML(`<span class="sub">` + template.HTMLEscapeString(account.Detail) + `</span>`)
	}
	toggle := plugui.Action{Label: "停用", Path: "pool",
		Query: url.Values{"action": {"disable"}, "name": {account.Name}}.Encode()}
	if account.Disabled {
		toggle = plugui.Action{Label: "启用", Path: "pool", Kind: "primary",
			Query: url.Values{"action": {"enable"}, "name": {account.Name}}.Encode()}
	}
	return []template.HTML{
		name,
		template.HTML(template.HTMLEscapeString(amountText(account.Available))),
		template.HTML(template.HTMLEscapeString(amountText(account.Balance))),
		template.HTML(template.HTMLEscapeString(amountText(account.DailyBalance))),
		template.HTML(template.HTMLEscapeString(checkin)),
		template.HTML(template.HTMLEscapeString(account.Status)),
		outcome,
		plugui.Buttons(toggle),
	}
}

// amountText renders one point figure. A figure the provider did not publish
// shows as 未知 rather than 0 — zero is a statement, unknown is not.
func amountText(value *float64) string {
	if value == nil {
		return "未知"
	}
	return fmt.Sprintf("%.0f", *value)
}

// actionText renders a sweep action for the table.
func actionText(action string) string {
	switch action {
	case actionNone:
		return "无变化"
	case actionDisabled:
		return "已停用"
	case actionEnabled:
		return "已恢复"
	case actionSkipped:
		return "跳过"
	case actionFailed:
		return "失败"
	case actionWriteGuard:
		return "写开关关闭"
	case "":
		return "—"
	default:
		return action
	}
}

// wantsJSON reports whether the requester asked for the machine-readable form.
func wantsJSON(request pluginapi.ManagementRequest) bool {
	if strings.EqualFold(strings.TrimSpace(request.Query.Get("format")), "json") {
		return true
	}
	return strings.Contains(strings.ToLower(request.Headers.Get("Accept")), "application/json")
}
