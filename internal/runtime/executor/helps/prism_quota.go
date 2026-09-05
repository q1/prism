package helps

import (
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strconv"
	"time"
)

type prismQuotaHTTPError struct{ status int }

func (e prismQuotaHTTPError) Error() string   { return "quota observation unavailable" }
func (e prismQuotaHTTPError) StatusCode() int { return e.status }

// ReadPrismQuotaResponse bounds usage data without exposing provider response bodies.
func ReadPrismQuotaResponse(provider string, response *http.Response) (http.Header, error) {
	if response == nil || response.Body == nil {
		return nil, errors.New("quota observation unavailable")
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, prismQuotaHTTPError{status: response.StatusCode}
	}
	body, errRead := io.ReadAll(io.LimitReader(response.Body, 128*1024+1))
	if errRead != nil || len(body) > 128*1024 {
		return nil, errors.New("quota observation invalid")
	}
	return PrismUsageHeaders(provider, body), nil
}

// PrismUsageHeaders maps provider usage responses into the same bounded passive
// observation contract as inference responses. Unknown fields stay unknown.
func PrismUsageHeaders(provider string, body []byte) http.Header {
	result := http.Header{}
	var root map[string]json.RawMessage
	if json.Unmarshal(body, &root) != nil {
		return result
	}
	if provider == "claude" {
		for _, window := range []struct{ field, suffix string }{{"five_hour", "5h"}, {"seven_day", "7d"}, {"seven_day_fable", "7d-fable"}, {"seven_day_oi", "7d_oi"}} {
			var measured struct {
				Utilization *float64 `json:"utilization"`
				ResetsAt    string   `json:"resets_at"`
			}
			if json.Unmarshal(root[window.field], &measured) != nil || measured.Utilization == nil || math.IsNaN(*measured.Utilization) || *measured.Utilization < 0 || *measured.Utilization > 100 {
				continue
			}
			reset, errReset := time.Parse(time.RFC3339Nano, measured.ResetsAt)
			if errReset != nil {
				continue
			}
			prefix := "Anthropic-Ratelimit-Unified-" + window.suffix + "-"
			result.Set(prefix+"Utilization", strconv.FormatFloat(*measured.Utilization/100, 'f', -1, 64))
			result.Set(prefix+"Reset", strconv.FormatInt(reset.Unix(), 10))
		}
	}
	if provider == "codex" {
		var rate struct {
			Primary   json.RawMessage `json:"primary_window"`
			Secondary json.RawMessage `json:"secondary_window"`
		}
		if json.Unmarshal(root["rate_limit"], &rate) != nil {
			return result
		}
		for _, window := range []struct {
			name string
			raw  json.RawMessage
		}{{"Primary", rate.Primary}, {"Secondary", rate.Secondary}} {
			var measured struct {
				UsedPercent *float64 `json:"used_percent"`
				Seconds     int64    `json:"limit_window_seconds"`
				ResetAt     int64    `json:"reset_at"`
			}
			if json.Unmarshal(window.raw, &measured) != nil || measured.UsedPercent == nil || *measured.UsedPercent < 0 || *measured.UsedPercent > 100 || measured.Seconds <= 0 || measured.Seconds%60 != 0 || measured.ResetAt <= 0 {
				continue
			}
			prefix := "X-Codex-" + window.name + "-"
			result.Set(prefix+"Used-Percent", strconv.FormatFloat(*measured.UsedPercent, 'f', -1, 64))
			result.Set(prefix+"Window-Minutes", strconv.FormatInt(measured.Seconds/60, 10))
			result.Set(prefix+"Reset-At", strconv.FormatInt(measured.ResetAt, 10))
		}
		var plan string
		if json.Unmarshal(root["plan_type"], &plan) == nil && validCodexQuotaEventText(plan) {
			result.Set("X-Codex-Plan-Type", plan)
		}
	}
	return result
}
