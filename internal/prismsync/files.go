package prismsync

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
)

type Recipient struct {
	ID           string   `json:"id"`
	Enabled      bool     `json:"enabled"`
	KeyFile      string   `json:"keyFile"`
	Accounts     []string `json:"accounts"`
	LeaseSeconds int      `json:"leaseSeconds"`
}

type PrimaryConfig struct {
	Schema           string      `json:"schema"`
	AuthorityID      string      `json:"authorityId"`
	Epoch            string      `json:"epoch"`
	StateDir         string      `json:"stateDir"`
	AuthDir          string      `json:"authDir"`
	EngineConfigFile string      `json:"engineConfigFile"`
	SigningKeyFile   string      `json:"signingKeyFile"`
	Recipients       []Recipient `json:"recipients"`
}

type ReceiverConfig struct {
	Schema string `json:"schema"`
	Binding
	StateDir      string `json:"stateDir"`
	KeyFile       string `json:"keyFile"`
	VerifyKeyFile string `json:"verifyKeyFile"`
}

// PrivateRead never follows a symlink or emits a path/parser error that could
// contain account identity or secret bytes. Configuration uses absolute paths.
func PrivateRead(path string, limit int64) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, ErrUnavailable
	}
	canonical, errCanonical := filepath.EvalSymlinks(path)
	info, errStat := os.Lstat(path)
	if errCanonical != nil || canonical != filepath.Clean(path) || errStat != nil || !info.Mode().IsRegular() || !privateOwner(info) || info.Mode().Perm()&0o077 != 0 || info.Size() > limit {
		return nil, ErrUnavailable
	}
	file, errOpen := os.Open(path)
	if errOpen != nil {
		return nil, ErrUnavailable
	}
	defer func() { _ = file.Close() }()
	opened, errOpened := file.Stat()
	if errOpened != nil || !os.SameFile(info, opened) {
		return nil, ErrUnavailable
	}
	data, errRead := io.ReadAll(io.LimitReader(file, limit+1))
	if errRead != nil || int64(len(data)) > limit {
		return nil, ErrUnavailable
	}
	return data, nil
}

func privateDir(path string) error {
	if !filepath.IsAbs(path) {
		return ErrUnavailable
	}
	canonical, errCanonical := filepath.EvalSymlinks(path)
	info, errStat := os.Lstat(path)
	if errCanonical != nil || canonical != filepath.Clean(path) || errStat != nil || !info.IsDir() || !privateOwner(info) || info.Mode().Perm()&0o077 != 0 {
		return ErrUnavailable
	}
	return nil
}

func syncDir(path string) error {
	file, errOpen := os.Open(path)
	if errOpen != nil {
		return ErrUnavailable
	}
	defer func() { _ = file.Close() }()
	if file.Sync() != nil {
		return ErrUnavailable
	}
	return nil
}

func atomicWrite(path string, data []byte) error {
	directory := filepath.Dir(path)
	if privateDir(directory) != nil {
		return ErrUnavailable
	}
	if info, errStat := os.Lstat(path); errStat == nil && (!info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0) {
		return ErrUnavailable
	}
	file, errCreate := os.CreateTemp(directory, ".prism-pending-")
	if errCreate != nil {
		return ErrUnavailable
	}
	name := file.Name()
	defer func() { _ = file.Close(); _ = os.Remove(name) }()
	if file.Chmod(0o600) != nil {
		return ErrUnavailable
	}
	if _, errWrite := file.Write(data); errWrite != nil {
		return ErrUnavailable
	}
	if file.Sync() != nil || file.Close() != nil || os.Rename(name, path) != nil {
		return ErrUnavailable
	}
	return syncDir(directory)
}

// WriteNew publishes only to a new private file; an export never overwrites an
// earlier bundle which an operator may already be transporting.
func WriteNew(path string, data []byte) error {
	if privateDir(filepath.Dir(path)) != nil {
		return ErrUnavailable
	}
	file, errCreate := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errCreate != nil {
		return ErrUnavailable
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, errWrite := file.Write(data); errWrite != nil {
		return ErrUnavailable
	}
	if file.Sync() != nil || file.Close() != nil || syncDir(filepath.Dir(path)) != nil {
		return ErrUnavailable
	}
	ok = true
	return nil
}

func locked(stateDir string, action func() error) error {
	if privateDir(stateDir) != nil {
		return ErrUnavailable
	}
	path := filepath.Join(stateDir, ".operation-lock")
	file, errCreate := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errCreate != nil {
		return ErrBusy
	}
	_ = file.Close()
	defer func() { _ = os.Remove(path) }()
	return action()
}

func LoadPrimary(path string) (PrimaryConfig, error) {
	var config PrimaryConfig
	data, errRead := PrivateRead(path, 128*1024)
	if errRead != nil || Decode(data, &config) != nil || config.Schema != "prism-serving-primary/v1" || !identifier.MatchString(config.AuthorityID) || !epochPattern.MatchString(config.Epoch) || len(config.Recipients) > 64 {
		return PrimaryConfig{}, ErrInvalid
	}
	seen := make(map[string]bool)
	for _, recipient := range config.Recipients {
		if !identifier.MatchString(recipient.ID) || seen[recipient.ID] || recipient.LeaseSeconds < 60 || recipient.LeaseSeconds > 86400 || len(recipient.Accounts) > MaxAccounts {
			return PrimaryConfig{}, ErrInvalid
		}
		seen[recipient.ID] = true
		for _, name := range recipient.Accounts {
			if name != "*" && !ValidAccountName(name) {
				return PrimaryConfig{}, ErrInvalid
			}
		}
	}
	return config, nil
}

func LoadReceiver(path string) (ReceiverConfig, error) {
	var config ReceiverConfig
	data, errRead := PrivateRead(path, 128*1024)
	if errRead != nil || Decode(data, &config) != nil || config.Schema != "prism-serving-receiver/v1" || !config.Binding.Valid() {
		return ReceiverConfig{}, ErrInvalid
	}
	return config, nil
}

func receiverKeys(config ReceiverConfig) ([]byte, ed25519.PublicKey, error) {
	key, errKey := PrivateRead(config.KeyFile, 32)
	verify, errVerify := PrivateRead(config.VerifyKeyFile, ed25519.PublicKeySize)
	if errKey != nil || len(key) != 32 || errVerify != nil || len(verify) != ed25519.PublicKeySize {
		return nil, nil, ErrUnavailable
	}
	return key, ed25519.PublicKey(verify), nil
}

// GenerateKeys creates a new isolated enrollment key set, never replacing keys.
// Only the public identity and epoch may be printed by callers.
func GenerateKeys(directory string) (string, error) {
	if privateDir(directory) != nil {
		return "", ErrUnavailable
	}
	verify, signing, errGenerate := ed25519.GenerateKey(rand.Reader)
	if errGenerate != nil {
		return "", ErrUnavailable
	}
	key, epoch := make([]byte, 32), make([]byte, 16)
	if _, errRandom := rand.Read(key); errRandom != nil {
		return "", ErrUnavailable
	}
	if _, errRandom := rand.Read(epoch); errRandom != nil {
		return "", ErrUnavailable
	}
	for _, entry := range []struct {
		name string
		data []byte
	}{{"primary-signing.key", signing}, {"primary-verify.key", verify}, {"recipient.key", key}} {
		if WriteNew(filepath.Join(directory, entry.name), entry.data) != nil {
			return "", ErrUnavailable
		}
	}
	return hex.EncodeToString(epoch), nil
}

func encode(value any) ([]byte, error) {
	data, errEncode := json.Marshal(value)
	if errEncode != nil || len(data) > MaxBytes {
		return nil, ErrInvalid
	}
	return append(data, '\n'), nil
}
