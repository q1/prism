package management

import (
	"context"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestQuotaStatusUsesMeasuredWindowsWithoutCredentialMaterial(t *testing.T) {
	manager := coreauth.NewManager(nil, &coreauth.RoundRobinSelector{}, nil)
	credential := &coreauth.Auth{ID: "account.json", FileName: "account.json", Provider: "codex", Metadata: map[string]any{"access_token": "test-private-access", "refresh_token": "test-private-refresh"}, Quota: coreauth.QuotaState{ObservedAt: time.Now(), Signals: map[string]string{"X-Codex-Primary-Window-Minutes": "300", "X-Codex-Primary-Used-Percent": "25"}}}
	if _, err := manager.Register(context.Background(), credential); err != nil {
		t.Fatal(err)
	}
	handler := NewHandlerWithoutConfigFilePath(&config.Config{}, manager)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	handler.GetQuotaSchedulerStatus(ctx)
	if recorder.Code != 200 {
		t.Fatal("quota endpoint failed")
	}
	var response struct {
		Accounts map[string]struct {
			Provider string                       `json:"provider"`
			FiveHour coreauth.ObservedQuotaWindow `json:"five_hour"`
		} `json:"accounts"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Accounts["account.json"].FiveHour.UsedPercent != 25 {
		t.Fatal("measured quota not returned")
	}
	if strings.Contains(recorder.Body.String(), "test-private-") {
		t.Fatal("quota endpoint exposed credential material")
	}
}
