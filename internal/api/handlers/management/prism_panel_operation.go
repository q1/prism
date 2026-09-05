package management

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type prismPanelOperation struct {
	fingerprint string
	revision    string
	status      int
	at          time.Time
}

// The protected standalone panel retains upstream management operations, but
// binds each write to an actor, operation and current settings revision. This
// method runs under the same mutex as the finite client control contract.
func (h *Handler) prismPanelOperation(c *gin.Context) {
	actor := c.GetHeader("X-Prism-Actor")
	if !prismActorID.MatchString(actor) {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "prism_invalid_actor"})
		return
	}
	mutating := c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead || strings.HasSuffix(c.Request.URL.Path, "-auth-url")
	if !mutating {
		c.Header("X-Prism-Settings-Revision", h.prismRevision())
		c.Next()
		return
	}
	operationID := c.GetHeader("X-Prism-Operation-Id")
	expected := c.GetHeader("X-Prism-Expected-Revision")
	if !prismOperationID.MatchString(operationID) || len(expected) != 64 {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "prism_invalid_operation"})
		return
	}
	var reader io.Reader = c.Request.Body
	if reader == nil {
		reader = bytes.NewReader(nil)
	}
	body, errRead := io.ReadAll(io.LimitReader(reader, 1_048_577))
	if errRead != nil || len(body) > 1_048_576 {
		c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{"error": "prism_request_too_large"})
		return
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(body))
	message := append([]byte(c.Request.Method+"\n"+c.Request.URL.RequestURI()+"\n"+expected+"\n"), body...)
	digest := sha256.Sum256(message)
	fingerprint := hex.EncodeToString(digest[:])
	key := actor + ":" + strings.ToLower(operationID)
	if prior, found := h.prismControl.panelOperations[key]; found {
		if prior.fingerprint != fingerprint {
			c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": "prism_operation_conflict"})
			return
		}
		c.Header("X-Prism-Settings-Revision", prior.revision)
		c.Header("X-Prism-Operation-Id", operationID)
		// Never retain secret-bearing upstream responses in the operation ledger.
		// The gateway retains its sanitized response for the live client retry.
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": "prism_operation_recorded", "operationStatus": "recorded", "originalStatus": prior.status})
		return
	}
	if expected != h.prismRevision() {
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": "prism_settings_conflict"})
		return
	}
	writer := &prismPanelWriter{ResponseWriter: c.Writer, headers: make(http.Header), status: http.StatusOK}
	original := c.Writer
	c.Writer = writer
	if !h.prismPanelConfigTransaction(c) && !h.prismPanelAccountTransaction(c) {
		c.Next()
	}
	c.Writer = original
	// Increment even for a partial upstream failure: retry must read actual state
	// rather than assume an old handler applied nothing before returning an error.
	h.prismControl.generation++
	revision := h.prismRevision()
	if len(h.prismControl.panelOperations) >= 2048 {
		var oldestKey string
		var oldest time.Time
		for key, value := range h.prismControl.panelOperations {
			if oldest.IsZero() || value.at.Before(oldest) {
				oldestKey, oldest = key, value.at
			}
		}
		delete(h.prismControl.panelOperations, oldestKey)
	}
	h.prismControl.panelOperations[key] = prismPanelOperation{fingerprint, revision, writer.status, time.Now()}
	for key, values := range writer.headers {
		original.Header()[key] = values
	}
	c.Header("X-Prism-Settings-Revision", revision)
	c.Header("X-Prism-Operation-Id", operationID)
	if writer.overflow {
		c.JSON(http.StatusBadGateway, gin.H{"error": "prism_response_too_large"})
		return
	}
	c.Data(writer.status, writer.headers.Get("Content-Type"), writer.body.Bytes())
}

type prismPanelWriter struct {
	gin.ResponseWriter
	headers  http.Header
	body     bytes.Buffer
	status   int
	written  bool
	overflow bool
}

func (w *prismPanelWriter) Header() http.Header { return w.headers }
func (w *prismPanelWriter) WriteHeader(status int) {
	if !w.written {
		w.status, w.written = status, true
	}
}
func (w *prismPanelWriter) WriteHeaderNow() { w.written = true }
func (w *prismPanelWriter) Status() int     { return w.status }
func (w *prismPanelWriter) Size() int       { return w.body.Len() }
func (w *prismPanelWriter) Written() bool   { return w.written }
func (w *prismPanelWriter) Write(body []byte) (int, error) {
	w.written = true
	if w.body.Len()+len(body) > 1_048_576 {
		w.overflow = true
		return len(body), nil
	}
	return w.body.Write(body)
}
func (w *prismPanelWriter) WriteString(body string) (int, error) { return w.Write([]byte(body)) }
func (w *prismPanelWriter) Flush()                               { w.written = true }
