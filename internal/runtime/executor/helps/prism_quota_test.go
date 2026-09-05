package helps

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestPrismUsageNormalizesMeasuredWindowsOnly(t *testing.T) {
	claude := PrismUsageHeaders("claude", []byte(`{"five_hour":{"utilization":20,"resets_at":"2027-01-01T12:00:00Z"},"seven_day_fable":{"utilization":97,"resets_at":"2027-01-02T12:00:00Z"},"seven_day_opus":{"utilization":100,"resets_at":"2027-01-02T12:00:00Z"}}`))
	if claude.Get("Anthropic-Ratelimit-Unified-5h-Utilization") != "0.2" || claude.Get("Anthropic-Ratelimit-Unified-7d-fable-Utilization") != "0.97" || claude.Get("Anthropic-Ratelimit-Unified-7d-Utilization") != "" {
		t.Fatal("Claude usage denominator or missing window changed")
	}
	codex := PrismUsageHeaders("codex", []byte(`{"rate_limit":{"primary_window":{"used_percent":35,"limit_window_seconds":18000,"reset_at":1800000000},"secondary_window":{"used_percent":51,"limit_window_seconds":604800,"reset_at":1800200000}},"plan_type":"pro"}`))
	if codex.Get("X-Codex-Primary-Window-Minutes") != "300" || codex.Get("X-Codex-Secondary-Window-Minutes") != "10080" || codex.Get("X-Codex-Primary-Used-Percent") != "35" {
		t.Fatal("Codex usage window identity changed")
	}
	if len(PrismUsageHeaders("grok", []byte(`{"five_hour":{"utilization":0}}`))) != 0 {
		t.Fatal("unsupported quota invented")
	}
}

func TestPrismQuotaReaderBoundsAndDoesNotExposeBody(t *testing.T) {
	_, err := ReadPrismQuotaResponse("claude", &http.Response{StatusCode: 401, Body: io.NopCloser(strings.NewReader("private provider error"))})
	if err == nil || strings.Contains(err.Error(), "private") {
		t.Fatal("error body escaped")
	}
	if status, ok := err.(interface{ StatusCode() int }); !ok || status.StatusCode() != 401 {
		t.Fatal("lost status classification")
	}
	_, err = ReadPrismQuotaResponse("claude", &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(strings.Repeat(" ", 128*1024+1)))})
	if err == nil {
		t.Fatal("unbounded usage response accepted")
	}
}
