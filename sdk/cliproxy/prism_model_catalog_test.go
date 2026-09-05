package cliproxy

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/api/handlers/management"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/watcher"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

type prismCatalogAvailability struct {
	ID             string `json:"id"`
	Available      bool   `json:"available"`
	UsableAccounts int    `json:"usableAccounts"`
	Reason         string `json:"reason"`
}

func readPrismCatalogAvailability(t *testing.T, cfg *config.Config, manager *coreauth.Manager) []prismCatalogAvailability {
	t.Helper()
	handler := management.NewHandlerWithoutConfigFilePath(cfg, manager)
	response := httptest.NewRecorder()
	request, _ := gin.CreateTestContext(response)
	handler.GetPrismModels(request)
	var body struct {
		Models []prismCatalogAvailability `json:"models"`
	}
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &body) != nil {
		t.Fatal("model availability failed")
	}
	return body.Models
}

func TestPrismDisabledAccountWatcherRetainsUnavailableModels(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Config{}
	cfg.Routing.PrismPolicy = true
	manager := coreauth.NewManager(nil, nil, nil)
	manager.SetConfig(cfg)
	service := &Service{cfg: cfg, coreManager: manager}
	account := &coreauth.Auth{ID: "prism-disabled-watch", Provider: "xai", Status: coreauth.StatusActive, Metadata: map[string]any{"type": "xai"}}
	modelRegistry := registry.GetGlobalRegistry()
	t.Cleanup(func() { modelRegistry.UnregisterClient(account.ID) })
	service.handleAuthUpdate(ctx, watcher.AuthUpdate{Action: watcher.AuthUpdateActionAdd, Auth: account})
	before := readPrismCatalogAvailability(t, cfg, manager)
	if len(before) == 0 || !before[0].Available {
		t.Fatal("native account did not initially expose usable models")
	}
	account = account.Clone()
	account.Disabled = true
	account.Status = coreauth.StatusDisabled
	service.handleAuthUpdate(ctx, watcher.AuthUpdate{Action: watcher.AuthUpdateActionModify, Auth: account})
	if len(modelRegistry.GetModelsForClient(account.ID)) != 0 {
		t.Fatal("disabled account remained registered for routing")
	}
	after := readPrismCatalogAvailability(t, cfg, manager)
	if len(after) != len(before) {
		t.Fatal("disabling the final account removed its model catalogue")
	}
	for i, model := range after {
		if model.ID != before[i].ID || model.Available || model.UsableAccounts != 0 || model.Reason != "disabled" {
			t.Fatalf("disabled model incorrectly described: %+v", model)
		}
	}
	service.handleAuthUpdate(ctx, watcher.AuthUpdate{Action: watcher.AuthUpdateActionDelete, ID: account.ID})
	if len(readPrismCatalogAvailability(t, cfg, manager)) != 0 {
		t.Fatal("deleted account remained in aggregate availability")
	}
}

func TestPrismDisabledColdCatalogUsesNativePlanExclusionsAliasesAndPrefix(t *testing.T) {
	for _, provider := range []string{"claude", "codex", "xai"} {
		t.Run(provider, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.ForceModelPrefix = true
			service := &Service{cfg: cfg}
			account := &coreauth.Auth{ID: "prism-cold-" + provider, Provider: provider, Prefix: "pool", Status: coreauth.StatusActive, Attributes: map[string]string{"auth_kind": "oauth", "plan_type": "free"}}
			modelRegistry := registry.GetGlobalRegistry()
			t.Cleanup(func() { modelRegistry.UnregisterClient(account.ID) })
			base, _ := service.prismNativeModelsForAuth(account, provider, "oauth", nil)
			if len(base) < 2 {
				t.Fatal("native model catalogue unexpectedly small")
			}
			account.Attributes["excluded_models"] = base[0].ID
			cfg.OAuthModelAlias = map[string][]config.OAuthModelAlias{provider: {{Name: base[1].ID, Alias: "chosen-model"}}}
			service.registerModelsForAuth(context.Background(), account)
			want := codexModelIDSet(modelRegistry.GetModelsForClient(account.ID))
			// Simulate a cold process with no previous model observation.
			modelRegistry.SetPrismModelCatalogForClient(account.ID, provider, nil)
			modelRegistry.UnregisterClient(account.ID)
			account.Disabled = true
			account.Status = coreauth.StatusDisabled
			service.registerModelsForAuth(context.Background(), account)
			got := codexModelIDSet(modelRegistry.GetPrismModelCatalogForClient(account.ID, provider))
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("disabled native mapping differs from live registration: got %#v, want %#v", got, want)
			}
			if _, ok := got["pool/"+base[0].ID]; ok {
				t.Fatal("disabled catalogue restored an excluded model")
			}
			if len(modelRegistry.GetModelsForClient(account.ID)) != 0 {
				t.Fatal("cold disabled catalogue registered a serving client")
			}
		})
	}
}

func TestPrismHistoricalDynamicCatalogNeverMakesAnUnregisteredModelUsable(t *testing.T) {
	cfg := &config.Config{}
	manager := coreauth.NewManager(nil, nil, nil)
	account := &coreauth.Auth{ID: "prism-dynamic-catalog", Provider: "custom-provider", Status: coreauth.StatusActive}
	if _, err := manager.Register(context.Background(), account); err != nil {
		t.Fatal(err)
	}
	modelRegistry := registry.GetGlobalRegistry()
	modelRegistry.RegisterClient(account.ID, account.Provider, []*ModelInfo{{ID: "dynamic-model"}})
	modelRegistry.UnregisterClient(account.ID)
	models := readPrismCatalogAvailability(t, cfg, manager)
	if len(models) != 1 || models[0].ID != "dynamic-model" || models[0].Available || models[0].UsableAccounts != 0 {
		t.Fatal("historical dynamic model claimed current serving support")
	}
	if len(modelRegistry.GetPrismModelCatalogForClient(account.ID, "different-provider")) != 0 {
		t.Fatal("a reused account ID inherited another provider's catalogue")
	}
}
