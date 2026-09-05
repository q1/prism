package management

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestPrismReplicaBlocksLegacyAndVersionedMutations(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := &Handler{cfg: &config.Config{PrismReplica: true}}
	for _, test := range []struct {
		method, path string
		status       int
	}{
		{http.MethodPost, "/v0/management/prism/control", 403}, {http.MethodPatch, "/v0/management/auth-files/fields", 403},
		{http.MethodPut, "/v0/management/config.yaml", 403}, {http.MethodGet, "/v0/management/anthropic-auth-url", 403},
		{http.MethodGet, "/v0/management/oauth-callback", 403}, {http.MethodPost, "/v0/management/oauth-callback", 403},
		{http.MethodGet, "/v0/management/prism/models", 200}, {http.MethodGet, "/v0/management/auth-files", 200},
	} {
		router := gin.New()
		router.Handle(test.method, test.path, handler.PrismReplicaMiddleware(), func(c *gin.Context) { c.Status(200) })
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(test.method, test.path, nil))
		if response.Code != test.status {
			t.Fatalf("replica %s %s returned %d", test.method, test.path, response.Code)
		}
	}
}
