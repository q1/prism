package management

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// PrismReplicaMiddleware rejects every mutating administration operation and
// OAuth start/callback, including legacy panel paths. The primary owns policy.
func (h *Handler) PrismReplicaMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		h.mu.Lock()
		replica := h.cfg != nil && h.cfg.PrismReplica
		h.mu.Unlock()
		if replica && ((c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead) ||
			strings.HasSuffix(c.Request.URL.Path, "-auth-url") || strings.Contains(c.Request.URL.Path, "oauth-callback")) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "prism_replica_read_only"})
			return
		}
		c.Next()
	}
}
