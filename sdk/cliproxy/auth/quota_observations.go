package auth

import (
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ObservedQuotaWindow is a provider measurement, never a locally guessed allowance.
type ObservedQuotaWindow struct {
	UsedPercent float64    `json:"used_percent"`
	ResetAt     *time.Time `json:"reset_at,omitempty"`
	Known       bool       `json:"known"`
	HardLimited bool       `json:"hard_limited"`
}

// ObservedQuotaWindows normalizes only supported subscription windows. A Codex
// primary window may be weekly; the provider's duration determines its identity.
func ObservedQuotaWindows(provider string, quota QuotaState, now time.Time) map[string]ObservedQuotaWindow {
	windows := make(map[string]ObservedQuotaWindow)
	headers := http.Header{}
	for key, value := range quota.Signals {
		headers.Set(key, value)
	}
	add := func(name, percent, reset, after string, fraction, limited bool) {
		value, err := strconv.ParseFloat(percent, 64)
		if err != nil && !limited {
			return
		}
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return
		}
		if fraction {
			value *= 100
		}
		value = math.Max(0, math.Min(100, value))
		if limited {
			value = 100
		}
		var deadline *time.Time
		if seconds, err := strconv.ParseInt(reset, 10, 64); err == nil && seconds > 0 {
			stamp := time.Unix(seconds, 0).UTC()
			deadline = &stamp
		} else if seconds, err := strconv.ParseInt(after, 10, 64); err == nil && seconds > 0 && seconds <= 366*24*60*60 && !quota.ObservedAt.IsZero() {
			stamp := quota.ObservedAt.Add(time.Duration(seconds) * time.Second).UTC()
			deadline = &stamp
		}
		known := deadline == nil || deadline.After(now)
		windows[name] = ObservedQuotaWindow{UsedPercent: value, ResetAt: deadline, Known: known, HardLimited: limited && known}
	}
	switch strings.ToLower(provider) {
	case "claude":
		for _, window := range []struct{ suffix, name string }{{"5h", "five_hour"}, {"7d", "seven_day"}, {"7d-fable", "fable"}} {
			prefix := "Anthropic-Ratelimit-Unified-" + window.suffix + "-"
			add(window.name, headers.Get(prefix+"Utilization"), headers.Get(prefix+"Reset"), "", true, headers.Get(prefix+"Status") == "rejected")
		}
	case "codex":
		// A named model's watermark must not block every model on an account.
		active := headers.Get("X-Codex-Active-Limit")
		if active != "" && active != "codex" {
			return windows
		}
		for _, part := range []string{"Primary", "Secondary"} {
			prefix := "X-Codex-" + part + "-"
			name := ""
			switch headers.Get(prefix + "Window-Minutes") {
			case "300":
				name = "five_hour"
			case "10080":
				name = "weekly"
			}
			if name != "" {
				add(name, headers.Get(prefix+"Used-Percent"), headers.Get(prefix+"Reset-At"), headers.Get(prefix+"Reset-After-Seconds"), false, false)
			}
		}
	}
	return windows
}

func observedQuotaBlocked(auth *Auth, now time.Time) (bool, time.Time) {
	var until time.Time
	for _, window := range ObservedQuotaWindows(auth.Provider, auth.Quota, now) {
		if window.Known && window.UsedPercent >= 100 && window.ResetAt != nil && window.ResetAt.After(until) {
			until = *window.ResetAt
		}
	}
	return !until.IsZero(), until
}
