package cliproxy

import (
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// prismNativeModelsForAuth is shared by live registration and disabled-account
// availability. It performs no provider I/O and preserves the same plan/config
// exclusions as live registration. Aliases and prefixes are applied by callers.
func (s *Service) prismNativeModelsForAuth(a *coreauth.Auth, provider, authKind string, excluded []string) ([]*ModelInfo, bool) {
	var models []*ModelInfo
	switch provider {
	case "claude":
		models = registry.GetClaudeModels()
		if entry := s.resolveConfigClaudeKey(a); entry != nil {
			if len(entry.Models) > 0 {
				models = buildClaudeConfigModels(entry)
			}
			if authKind == "apikey" {
				excluded = entry.ExcludedModels
			}
		}
		models = applyExcludedModels(models, excluded)
	case "codex":
		if authKind == "apikey" {
			if entry := s.resolveConfigCodexKey(a); entry != nil {
				models = buildCodexConfigModels(entry)
				excluded = entry.ExcludedModels
			}
			models = applyExcludedModels(models, excluded)
			break
		}

		codexPlanType := ""
		if a.Attributes != nil {
			codexPlanType = strings.TrimSpace(a.Attributes["plan_type"])
		}
		switch strings.ToLower(codexPlanType) {
		case "pro":
			models = registry.GetCodexProModels()
		case "plus":
			models = registry.GetCodexPlusModels()
		case "team", "business", "go":
			models = registry.GetCodexTeamModels()
		case "free":
			models = registry.GetCodexFreeModels()
		default:
			models = registry.GetCodexProModels()
		}
		models = applyExcludedModels(models, excluded)
	case "xai":
		models = registry.GetXAIModels()
		if entry := s.resolveConfigXAIKey(a); entry != nil {
			if len(entry.Models) > 0 {
				models = buildXAIConfigModels(entry)
			}
			if authKind == "apikey" {
				excluded = entry.ExcludedModels
			}
		}
		models = applyExcludedModels(models, excluded)

	default:
		return nil, false
	}
	return models, true
}
