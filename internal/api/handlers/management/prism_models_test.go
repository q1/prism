package management

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestPrismModelAggregateScopesQuotaAndHidesAccounts(t *testing.T) {
	now := time.Now()
	manager := coreauth.NewManager(nil, &coreauth.ResetPrioritySelector{}, nil)
	a := &coreauth.Auth{ID: "private-file.json", FileName: "private-file.json", Provider: "claude", Label: "private-label", Metadata: map[string]any{"access_token": "private-secret", "email": "private@example.test"}, Quota: coreauth.QuotaState{ObservedAt: now, Signals: map[string]string{
		"Anthropic-Ratelimit-Unified-5h-Utilization":    "0.2",
		"Anthropic-Ratelimit-Unified-5h-Reset":          strconv.FormatInt(now.Add(time.Hour).Unix(), 10),
		"Anthropic-Ratelimit-Unified-7d-Utilization":    "0.2",
		"Anthropic-Ratelimit-Unified-7d-Reset":          strconv.FormatInt(now.Add(24*time.Hour).Unix(), 10),
		"Anthropic-Ratelimit-Unified-7d_oi-Utilization": "0.98",
		"Anthropic-Ratelimit-Unified-7d_oi-Reset":       strconv.FormatInt(now.Add(24*time.Hour).Unix(), 10),
	}}}
	if _, err := manager.Register(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(a.ID, "claude", []*registry.ModelInfo{{ID: "claude-opus-4-6"}, {ID: "claude-fable-5-1"}})
	t.Cleanup(func() { reg.UnregisterClient(a.ID) })
	h := NewHandlerWithoutConfigFilePath(&config.Config{}, manager)
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	h.GetPrismModels(ctx)
	if rec.Code != http.StatusOK {
		t.Fatal("aggregate failed")
	}
	if strings.Contains(rec.Body.String(), "private") {
		t.Fatal("aggregate leaked account detail")
	}
	var payload struct {
		ObservedAt time.Time                `json:"observedAt"`
		Models     []prismModelAvailability `json:"models"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.ObservedAt.IsZero() || len(payload.Models) != 2 {
		t.Fatalf("unexpected aggregate: %+v", payload)
	}
	for _, model := range payload.Models {
		if model.ID == "claude-fable-5-1" && (model.Available || model.UsableAccounts != 0 || model.Reason != "reserve_avoided") {
			t.Fatal("Fable reserve not reflected")
		}
		if model.ID == "claude-opus-4-6" && (!model.Available || model.UsableAccounts != 1 || model.Reason != "") {
			t.Fatal("Fable reserve disabled Opus")
		}
	}
}

func TestPrismReservePatchValidationAndReadback(t *testing.T) {
	for _, tc := range []struct {
		value  string
		status int
		want   *float64
	}{
		{"null", 200, nil}, {"0", 200, prismTestPercent(0)}, {"3.5", 200, prismTestPercent(3.5)}, {"100", 200, prismTestPercent(100)},
		{"-1", 400, prismTestPercent(3)}, {"101", 400, prismTestPercent(3)}, {`"3"`, 400, prismTestPercent(3)}, {"true", 400, prismTestPercent(3)},
	} {
		t.Run(tc.value, func(t *testing.T) {
			store := &memoryAuthStore{}
			manager := coreauth.NewManager(store, nil, nil)
			a := &coreauth.Auth{ID: "reserve-test.json", FileName: "reserve-test.json", Provider: "claude", Metadata: map[string]any{"type": "claude"}, Attributes: map[string]string{"path": "/tmp/reserve-test.json"}}
			if _, err := manager.Register(context.Background(), a); err != nil {
				t.Fatal(err)
			}
			h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
			rec := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(rec)
			ctx.Request = httptest.NewRequest(http.MethodPatch, "/v0/management/auth-files/fields", strings.NewReader(`{"name":"reserve-test.json","reserve_percent":`+tc.value+`}`))
			h.PatchAuthFileFields(ctx)
			if rec.Code != tc.status {
				t.Fatalf("status %d, want %d", rec.Code, tc.status)
			}
			updated, _ := manager.GetByID(a.ID)
			actual := coreauth.PrismReservePercent(updated)
			if (actual == nil) != (tc.want == nil) || (actual != nil && *actual != *tc.want) {
				t.Fatalf("reserve %v, want %v", actual, tc.want)
			}
			entry := h.buildAuthFileEntry(updated)
			if _, ok := entry["reserve_percent"]; !ok {
				t.Fatal("missing admin reserve readback")
			}
			if _, ok := entry["quota_windows"]; !ok {
				t.Fatal("missing normalized quota windows")
			}
		})
	}
}

func prismTestPercent(value float64) *float64 { return &value }
