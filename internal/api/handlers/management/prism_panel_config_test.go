package management

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"gopkg.in/yaml.v3"
)

type prismBlockedBody struct {
	io.Reader
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *prismBlockedBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.entered); <-b.release })
	return b.Reader.Read(p)
}
func (*prismBlockedBody) Close() error { return nil }

func TestPrismPanelConfigStagesBeforeCommitAndPreservesConcurrentState(t *testing.T) {
	for _, mutation := range []string{"config", "account"} {
		t.Run(mutation, func(t *testing.T) {
			handler, router, manager := controlFixture(t)
			revision := controlRevision(t, router)
			body := &prismBlockedBody{Reader: strings.NewReader(`{"value":"fill-first"}`), entered: make(chan struct{}), release: make(chan struct{})}
			response := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(response)
			ctx.Request = httptest.NewRequest(http.MethodPut, "/v0/management/routing/strategy", body)
			ctx.Request.Header.Set("Content-Type", "application/json")
			ctx.Request.Header.Set("X-Prism-Expected-Revision", revision)
			finished := make(chan bool, 1)
			go func() { finished <- handler.prismPanelConfigTransaction(ctx) }()
			<-body.entered // The candidate has been cloned; validation has not completed.
			if mutation == "config" {
				newer := handler.cfg.CloneForRuntime()
				newer.Debug = true
				if errSave := config.SaveConfigPreserveComments(handler.configFilePath, newer); errSave != nil {
					t.Fatal(errSave)
				}
				handler.SetConfig(newer)
			} else {
				weight := 7
				if _, errEdit := manager.UpdateAccountPolicy(context.Background(), "test.json", coreauth.AccountPolicyPatch{Weight: &weight}); errEdit != nil {
					t.Fatal(errEdit)
				}
			}
			before, errRead := os.ReadFile(handler.configFilePath)
			if errRead != nil {
				t.Fatal(errRead)
			}
			close(body.release)
			if !<-finished || response.Code != http.StatusConflict {
				t.Fatalf("concurrent %s update was overwritten (status %d)", mutation, response.Code)
			}
			after, _ := os.ReadFile(handler.configFilePath)
			if string(before) != string(after) || handler.cfg.Routing.Strategy != "round-robin" {
				t.Fatal("stale transaction published runtime or disk state")
			}
		})
	}
}

func TestPrismPanelConfigSuccessfulCommitReloadsOnceAndProtectsHostWiring(t *testing.T) {
	handler, router, _ := controlFixture(t)
	router.PUT("/v0/management/config.yaml", handler.PrismControlMiddleware(), handler.PutConfigYAML)
	var reloads atomic.Int32
	handler.SetConfigReloadHook(func(context.Context, *config.Config) { reloads.Add(1) })
	revision := controlRevision(t, router)
	response := panelCall(router, http.MethodPut, "/v0/management/routing/strategy", revision, "00000000-0000-4000-8000-000000000010", `{"value":"fill-first"}`)
	if response.Code != http.StatusOK || handler.cfg.Routing.Strategy != "fill-first" || reloads.Load() != 1 {
		t.Fatalf("staged config not committed exactly once: %d", response.Code)
	}
	persisted, errLoad := config.LoadConfig(handler.configFilePath)
	if errLoad != nil || persisted.Routing.Strategy != "fill-first" {
		t.Fatal("acknowledged config was not persisted")
	}
	before, _ := os.ReadFile(handler.configFilePath)
	attempt := persisted.CloneForRuntime()
	attempt.Host = "0.0.0.0"
	encoded, _ := yaml.Marshal(attempt)
	response = panelCall(router, http.MethodPut, "/v0/management/config.yaml", controlRevision(t, router), "00000000-0000-4000-8000-000000000011", string(encoded))
	after, _ := os.ReadFile(handler.configFilePath)
	if response.Code != http.StatusConflict || string(before) != string(after) || handler.cfg.Host == "0.0.0.0" || reloads.Load() != 1 {
		t.Fatalf("raw config did not return a safe wiring conflict: status=%d body=%s changed=%v hostChanged=%v reloads=%d", response.Code, response.Body.String(), string(before) != string(after), handler.cfg.Host == "0.0.0.0", reloads.Load())
	}
}

func TestPrismPanelRevisionIncludesNonJSONRuntimeWiringAndAdvancedPolicy(t *testing.T) {
	for _, field := range []string{"host", "port", "auth-dir", "management", "headers", "note", "request_retry"} {
		t.Run(field, func(t *testing.T) {
			handler, router, manager := controlFixture(t)
			revision := controlRevision(t, router)
			cfg := handler.cfg.CloneForRuntime()
			switch field {
			case "host":
				cfg.Host = "127.0.0.2"
			case "port":
				cfg.Port = 1234
			case "auth-dir":
				cfg.AuthDir += "-changed"
			case "management":
				cfg.RemoteManagement.AllowRemote = true
			default:
				account, _ := manager.GetByID("test.json")
				account.Metadata[field] = "fixture-policy"
				_, _ = manager.Update(context.Background(), account)
			}
			handler.SetConfig(cfg)
			if revision == controlRevision(t, router) {
				t.Fatal("revision omitted changed policy or host field")
			}
		})
	}
}
