package registry

import "strings"

type prismClientCatalog struct {
	provider string
	models   []*ModelInfo
}

// SetPrismModelCatalogForClient records supported model identifiers without
// registering a serving client. Disabled native accounts use their normal
// config/plan/alias mapping here, including on a cold start.
func (r *ModelRegistry) SetPrismModelCatalogForClient(clientID, provider string, models []*ModelInfo) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.setPrismModelCatalogLocked(clientID, provider, models)
}

func (r *ModelRegistry) setPrismModelCatalogLocked(clientID, provider string, models []*ModelInfo) {
	if r.prismClientCatalogs == nil {
		r.prismClientCatalogs = make(map[string]prismClientCatalog)
	}
	if len(models) == 0 {
		delete(r.prismClientCatalogs, clientID)
		return
	}
	seen := make(map[string]bool, len(models))
	catalog := prismClientCatalog{provider: strings.ToLower(strings.TrimSpace(provider))}
	for _, model := range models {
		if model == nil || model.ID == "" || seen[model.ID] {
			continue
		}
		seen[model.ID] = true
		catalog.models = append(catalog.models, cloneModelInfo(model))
	}
	r.prismClientCatalogs[clientID] = catalog
}

// GetPrismModelCatalogForClient returns only the same provider's last supported
// catalogue. Callers must independently verify active registration before
// reporting a model usable. Account deletion is filtered by the manager's live
// inventory; a reused ID with a different provider cannot inherit the catalogue.
func (r *ModelRegistry) GetPrismModelCatalogForClient(clientID, provider string) []*ModelInfo {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	catalog := r.prismClientCatalogs[clientID]
	if catalog.provider != strings.ToLower(strings.TrimSpace(provider)) {
		return nil
	}
	models := make([]*ModelInfo, 0, len(catalog.models))
	for _, model := range catalog.models {
		models = append(models, cloneModelInfo(model))
	}
	return models
}
