package prismsync

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
)

func materializedDigest(payload Payload) string {
	payload.Accounts = append([]Account{}, payload.Accounts...)
	sort.Slice(payload.Accounts, func(i, j int) bool { return payload.Accounts[i].Name < payload.Accounts[j].Name })
	data, _ := encode(payload)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// A lease renewal can keep an existing process only when all signed settings,
// credentials, token expirations, inventory and owner policy remain identical.
// The sole excluded value is the signed serving lease's own expiration.
func renewalDigest(payload Payload) string {
	copyPayload := Payload{Settings: payload.Settings, Accounts: make([]Account, 0, len(payload.Accounts))}
	for _, account := range payload.Accounts {
		var metadata map[string]any
		if json.Unmarshal(account.Credential, &metadata) != nil {
			return ""
		}
		delete(metadata, "prism_serving_expires_at")
		encoded, errEncode := json.Marshal(metadata)
		if errEncode != nil {
			return ""
		}
		copyPayload.Accounts = append(copyPayload.Accounts, Account{Name: account.Name, Credential: encoded})
	}
	return materializedDigest(copyPayload)
}

// MaterializeRuntime copies a verified immutable generation into the engine's
// private working tree. On same-content renewal the existing watcher sees only
// lease extensions; credentials and policy changes still require process fencing.
// Validate every source byte before writing any destination. A failed write
// requires the supervisor to stop the process, never continue on partial state.
func MaterializeRuntime(receipt Receipt, directory string) error {
	if privateDir(directory) != nil || receipt.materializedDigest == "" {
		return ErrUnavailable
	}
	entries, errRead := os.ReadDir(receipt.AuthDir)
	if errRead != nil || len(entries) != receipt.Accounts {
		return ErrUnavailable
	}
	payload := Payload{Settings: receipt.Settings, Accounts: make([]Account, 0, len(entries))}
	for _, entry := range entries {
		if !ValidAccountName(entry.Name()) {
			return ErrInvalid
		}
		data, errRead := PrivateRead(filepath.Join(receipt.AuthDir, entry.Name()), 256*1024)
		if errRead != nil {
			return errRead
		}
		payload.Accounts = append(payload.Accounts, Account{Name: entry.Name(), Credential: data})
	}
	if materializedDigest(payload) != receipt.materializedDigest {
		return ErrInvalid
	}
	for _, account := range payload.Accounts {
		if atomicWrite(filepath.Join(directory, account.Name), account.Credential) != nil {
			return ErrUnavailable
		}
	}
	return nil
}
