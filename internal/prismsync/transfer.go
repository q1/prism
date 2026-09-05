package prismsync

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

type sourceState struct {
	AuthorityID string `json:"authorityId"`
	Epoch       string `json:"epoch"`
	Generation  uint64 `json:"generation"`
}

type Receipt struct {
	Generation         uint64 `json:"generation"`
	ContentDigest      string `json:"contentDigest"`
	materializedDigest string
	Digest             string   `json:"digest"`
	ExpiresAt          int64    `json:"expiresAt"`
	Accounts           int      `json:"accounts"`
	AuthDir            string   `json:"authDir,omitempty"`
	Settings           Settings `json:"settings"`
}

func inventory(config PrimaryConfig, recipient Recipient) ([]Account, map[string]string, error) {
	if privateDir(config.AuthDir) != nil {
		return nil, nil, ErrUnavailable
	}
	entries, errRead := os.ReadDir(config.AuthDir)
	if errRead != nil {
		return nil, nil, ErrUnavailable
	}
	allowed := make(map[string]bool)
	for _, name := range recipient.Accounts {
		allowed[name] = true
	}
	accounts := make([]Account, 0)
	digests := make(map[string]string)
	for _, entry := range entries {
		name := entry.Name()
		if !ValidAccountName(name) || (!allowed["*"] && !allowed[name]) {
			continue
		}
		data, errRead := PrivateRead(filepath.Join(config.AuthDir, name), 256*1024)
		if errRead != nil {
			return nil, nil, ErrUnavailable
		}
		var authority map[string]any
		if json.Unmarshal(data, &authority) != nil || authority == nil {
			return nil, nil, ErrInvalid
		}
		if _, delegated := authority["prism_serving_expires_at"]; delegated || authority["refresh_disabled"] == true {
			return nil, nil, ErrInvalid
		}
		digest := sha256.Sum256(data)
		digests[name] = hex.EncodeToString(digest[:])
		accounts = append(accounts, Account{Name: name, Credential: json.RawMessage(data)})
	}
	sort.Slice(accounts, func(i, j int) bool { return accounts[i].Name < accounts[j].Name })
	return accounts, digests, nil
}

// Export advances durable generation before returning ciphertext. A failure can
// skip a number; it cannot issue two different manifests under one generation.
func Export(config PrimaryConfig, recipientID string, settings Settings, now time.Time) (Envelope, error) {
	var result Envelope
	if !identifier.MatchString(config.AuthorityID) || !epochPattern.MatchString(config.Epoch) || !validSettings(settings) {
		return result, ErrInvalid
	}
	var recipient *Recipient
	for index := range config.Recipients {
		if config.Recipients[index].ID == recipientID && config.Recipients[index].Enabled {
			recipient = &config.Recipients[index]
		}
	}
	if recipient == nil || recipient.LeaseSeconds < 60 || recipient.LeaseSeconds > 86400 {
		return result, ErrUnavailable
	}
	key, errKey := PrivateRead(recipient.KeyFile, 32)
	signing, errSigning := PrivateRead(config.SigningKeyFile, ed25519.PrivateKeySize)
	if errKey != nil || len(key) != 32 || errSigning != nil || len(signing) != ed25519.PrivateKeySize {
		return result, ErrUnavailable
	}
	errExport := locked(config.StateDir, func() error {
		state := sourceState{AuthorityID: config.AuthorityID, Epoch: config.Epoch}
		statePath := filepath.Join(config.StateDir, "primary-generation.json")
		if _, errStat := os.Lstat(statePath); errStat == nil {
			data, errRead := PrivateRead(statePath, 4096)
			if errRead != nil || Decode(data, &state) != nil || state.AuthorityID != config.AuthorityID || state.Epoch != config.Epoch {
				return ErrInvalid
			}
		} else if !os.IsNotExist(errStat) {
			return ErrUnavailable
		}
		if state.Generation == math.MaxUint64 {
			return ErrUnavailable
		}
		accounts, before, errInventory := inventory(config, *recipient)
		if errInventory != nil {
			return errInventory
		}
		state.Generation++
		header := Header{Schema: Schema, AuthorityID: config.AuthorityID, Epoch: config.Epoch, RecipientID: recipientID,
			Generation: state.Generation, IssuedAt: now.Unix(), ExpiresAt: now.Unix() + int64(recipient.LeaseSeconds)}
		envelope, errSeal := Seal(header, Payload{Settings: settings, Accounts: accounts}, key, signing)
		if errSeal != nil {
			return errSeal
		}
		_, after, errAfter := inventory(config, *recipient)
		if errAfter != nil || !reflect.DeepEqual(before, after) {
			return ErrUnavailable
		}
		data, _ := encode(state)
		if atomicWrite(statePath, data) != nil {
			return ErrUnavailable
		}
		result = envelope
		return nil
	})
	return result, errExport
}

func accepted(config ReceiverConfig, now time.Time, allowExpired bool) (Envelope, Payload, bool, error) {
	path := filepath.Join(config.StateDir, "accepted.json")
	if _, errStat := os.Lstat(path); os.IsNotExist(errStat) {
		return Envelope{}, Payload{}, false, nil
	}
	data, errRead := PrivateRead(path, MaxBytes)
	var envelope Envelope
	if errRead != nil || Decode(data, &envelope) != nil {
		return Envelope{}, Payload{}, false, ErrUnavailable
	}
	key, verify, errKeys := receiverKeys(config)
	if errKeys != nil {
		return Envelope{}, Payload{}, false, errKeys
	}
	payload, errOpen := open(envelope, config.Binding, key, verify, now, allowExpired)
	return envelope, payload, true, errOpen
}

// Import validates all credentials before changing durable or active state.
// accepted.json is both the encrypted journal and the monotonic generation fence.
func Import(config ReceiverConfig, envelope Envelope, now time.Time) (Receipt, error) {
	var receipt Receipt
	key, verify, errKeys := receiverKeys(config)
	if errKeys != nil {
		return receipt, errKeys
	}
	payload, errOpen := Open(envelope, config.Binding, key, verify, now)
	if errOpen != nil {
		return receipt, errOpen
	}
	errImport := locked(config.StateDir, func() error {
		previous, _, exists, errPrevious := accepted(config, now, true)
		if errPrevious != nil {
			return errPrevious
		}
		if exists && (envelope.Header.Generation < previous.Header.Generation || (envelope.Header.Generation == previous.Header.Generation && Digest(envelope) != Digest(previous))) {
			return ErrReplay
		}
		generationDir, errStage := stage(config, envelope, payload)
		if errStage != nil {
			return errStage
		}
		data, _ := encode(envelope)
		if atomicWrite(filepath.Join(config.StateDir, "accepted.json"), data) != nil {
			return ErrUnavailable
		}
		if publish(config, generationDir) != nil {
			return ErrUnavailable
		}
		receipt = makeReceipt(envelope, payload, generationDir)
		return nil
	})
	return receipt, errImport
}

// Current verifies the durable journal at every supervisor startup and repairs
// a crash after journal commit but before the current-generation pointer switch.
func Current(config ReceiverConfig, now time.Time) (Receipt, error) {
	var receipt Receipt
	errCurrent := locked(config.StateDir, func() error {
		envelope, payload, exists, errRead := accepted(config, now, false)
		if errRead != nil {
			return errRead
		}
		if !exists {
			return ErrUnavailable
		}
		directory, errStage := stage(config, envelope, payload)
		if errStage != nil {
			return errStage
		}
		if publish(config, directory) != nil {
			return ErrUnavailable
		}
		receipt = makeReceipt(envelope, payload, directory)
		return nil
	})
	return receipt, errCurrent
}

func makeReceipt(envelope Envelope, payload Payload, directory string) Receipt {
	return Receipt{Generation: envelope.Header.Generation, Digest: Digest(envelope), ContentDigest: renewalDigest(payload), materializedDigest: materializedDigest(payload), ExpiresAt: envelope.Header.ExpiresAt,
		Accounts: len(payload.Accounts), AuthDir: filepath.Join(directory, "auths"), Settings: payload.Settings}
}

func stage(config ReceiverConfig, envelope Envelope, payload Payload) (string, error) {
	root := filepath.Join(config.StateDir, "generations")
	if errCreate := os.Mkdir(root, 0o700); errCreate != nil && !os.IsExist(errCreate) {
		return "", ErrUnavailable
	}
	if privateDir(root) != nil {
		return "", ErrUnavailable
	}
	// Time may remove an expired credential from the same signed inventory.
	// Include the materialized content digest so startup can exclude it without
	// ever rewriting an immutable generation already used by a running engine.
	materialized, _ := encode(payload)
	payloadDigest := sha256.Sum256(materialized)
	name := strconv.FormatUint(envelope.Header.Generation, 10) + "-" + Digest(envelope) + "-" + hex.EncodeToString(payloadDigest[:])
	directory := filepath.Join(root, name)
	if _, errStat := os.Lstat(directory); errStat == nil {
		if validateGeneration(directory, payload) != nil {
			return "", ErrUnavailable
		}
		return directory, nil
	}
	staging, errCreate := os.MkdirTemp(root, ".pending-")
	if errCreate != nil {
		return "", ErrUnavailable
	}
	defer func() { _ = os.RemoveAll(staging) }()
	if os.Mkdir(filepath.Join(staging, "auths"), 0o700) != nil {
		return "", ErrUnavailable
	}
	for _, account := range payload.Accounts {
		if WriteNew(filepath.Join(staging, "auths", account.Name), account.Credential) != nil {
			return "", ErrUnavailable
		}
	}
	settings, _ := encode(payload.Settings)
	if WriteNew(filepath.Join(staging, "settings.json"), settings) != nil || syncDir(staging) != nil {
		return "", ErrUnavailable
	}
	if os.Rename(staging, directory) != nil || syncDir(root) != nil {
		return "", ErrUnavailable
	}
	return directory, nil
}

func validateGeneration(directory string, payload Payload) error {
	if privateDir(directory) != nil || privateDir(filepath.Join(directory, "auths")) != nil {
		return ErrUnavailable
	}
	entries, errRead := os.ReadDir(filepath.Join(directory, "auths"))
	if errRead != nil || len(entries) != len(payload.Accounts) {
		return ErrUnavailable
	}
	for _, account := range payload.Accounts {
		data, errRead := PrivateRead(filepath.Join(directory, "auths", account.Name), 256*1024)
		if errRead != nil || !bytes.Equal(data, account.Credential) {
			return ErrUnavailable
		}
	}
	settings, _ := encode(payload.Settings)
	data, errRead := PrivateRead(filepath.Join(directory, "settings.json"), 4096)
	if errRead != nil || !bytes.Equal(settings, data) {
		return ErrUnavailable
	}
	return nil
}

func publish(config ReceiverConfig, directory string) error {
	current := filepath.Join(config.StateDir, "current")
	if info, errStat := os.Lstat(current); errStat == nil && info.Mode()&os.ModeSymlink == 0 {
		return ErrUnavailable
	}
	relative, errRelative := filepath.Rel(config.StateDir, directory)
	if errRelative != nil || !strings.HasPrefix(relative, "generations"+string(os.PathSeparator)) {
		return ErrUnavailable
	}
	if existing, errRead := os.Readlink(current); errRead == nil && existing == relative {
		return nil
	}
	file, errCreate := os.CreateTemp(config.StateDir, ".current-")
	if errCreate != nil {
		return ErrUnavailable
	}
	temporary := file.Name()
	_ = file.Close()
	_ = os.Remove(temporary)
	defer func() { _ = os.Remove(temporary) }()
	if os.Symlink(relative, temporary) != nil || os.Rename(temporary, current) != nil {
		return ErrUnavailable
	}
	return syncDir(config.StateDir)
}
