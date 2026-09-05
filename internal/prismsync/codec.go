// Package prismsync provides explicit, one-way serving credential distribution.
// It has no dependency on q1code and never exports OAuth refresh credentials.
package prismsync

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"
)

const Schema = "prism-serving/v1"
const MaxBytes = 16 * 1024 * 1024
const MaxAccounts = 2048

var ErrInvalid = errors.New("serving snapshot is invalid")
var ErrExpired = errors.New("serving snapshot lease expired")
var ErrReplay = errors.New("serving snapshot generation was already superseded")
var ErrUnavailable = errors.New("private serving snapshot state is unavailable")
var ErrBusy = errors.New("serving snapshot state is locked by another operation")
var identifier = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)
var epochPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

type Settings struct {
	Strategy         string `json:"strategy"`
	SessionAffinity  bool   `json:"sessionAffinity"`
	RequestRetry     int    `json:"requestRetry"`
	MaxRetryInterval int    `json:"maxRetryInterval"`
}

type Account struct {
	Name       string          `json:"name"`
	Credential json.RawMessage `json:"credential"`
}

type Payload struct {
	Settings Settings  `json:"settings"`
	Accounts []Account `json:"accounts"`
}

// Header is authenticated by both AEAD and the primary's signature.
type Header struct {
	Schema      string `json:"schema"`
	AuthorityID string `json:"authorityId"`
	Epoch       string `json:"epoch"`
	RecipientID string `json:"recipientId"`
	Generation  uint64 `json:"generation"`
	IssuedAt    int64  `json:"issuedAt"`
	ExpiresAt   int64  `json:"expiresAt"`
}

type Envelope struct {
	Header     Header `json:"header"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
	Signature  string `json:"signature"`
}

type Binding struct {
	AuthorityID string `json:"authorityId"`
	Epoch       string `json:"epoch"`
	RecipientID string `json:"recipientId"`
}

func (binding Binding) Valid() bool {
	return identifier.MatchString(binding.AuthorityID) && epochPattern.MatchString(binding.Epoch) && identifier.MatchString(binding.RecipientID)
}

func ValidAccountName(name string) bool {
	return len(name) > 5 && len(name) <= 256 && !strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".json") &&
		!strings.ContainsAny(name, `/\\`) && strings.IndexFunc(name, func(r rune) bool { return r < 32 || r == 127 }) < 0
}

func validSettings(settings Settings) bool {
	switch settings.Strategy {
	case "round-robin", "weighted-round-robin", "fill-first", "reset-priority":
	default:
		return false
	}
	return settings.RequestRetry >= 0 && settings.RequestRetry <= 10 && settings.MaxRetryInterval >= 0 && settings.MaxRetryInterval <= 300
}

func Decode(data []byte, target any) error {
	if len(data) > MaxBytes {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || decoder.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	return nil
}

func aad(header Header) []byte {
	data, _ := json.Marshal(header)
	return append([]byte(Schema+"\x00header\x00"), data...)
}

func signedBytes(envelope Envelope) []byte {
	envelope.Signature = ""
	data, _ := json.Marshal(envelope)
	return append([]byte(Schema+"\x00signature\x00"), data...)
}

func Digest(envelope Envelope) string {
	data, _ := json.Marshal(envelope)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func Seal(header Header, payload Payload, encryptionKey []byte, signingKey ed25519.PrivateKey) (Envelope, error) {
	var empty Envelope
	if len(encryptionKey) != 32 || len(signingKey) != ed25519.PrivateKeySize || !validHeader(header) || !validSettings(payload.Settings) || len(payload.Accounts) > MaxAccounts {
		return empty, ErrInvalid
	}
	cleaned, errClean := cleanPayload(payload, time.Unix(header.IssuedAt, 0), time.Unix(header.ExpiresAt, 0))
	if errClean != nil {
		return empty, errClean
	}
	plain, errEncode := json.Marshal(cleaned)
	if errEncode != nil || len(plain) > MaxBytes/2 {
		return empty, ErrInvalid
	}
	block, _ := aes.NewCipher(encryptionKey)
	aead, _ := cipher.NewGCM(block)
	nonce := make([]byte, aead.NonceSize())
	if _, errRandom := rand.Read(nonce); errRandom != nil {
		return empty, ErrUnavailable
	}
	envelope := Envelope{Header: header, Nonce: base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, plain, aad(header)))}
	envelope.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(signingKey, signedBytes(envelope)))
	return envelope, nil
}

func validHeader(header Header) bool {
	return header.Schema == Schema && (Binding{header.AuthorityID, header.Epoch, header.RecipientID}).Valid() && header.Generation > 0 &&
		header.IssuedAt > 0 && header.ExpiresAt > header.IssuedAt && header.ExpiresAt-header.IssuedAt <= 24*60*60
}

// Open verifies the pinned authority before decrypting. Expired ciphertext may
// be inspected only internally to preserve the durable generation high-water.
func Open(envelope Envelope, binding Binding, encryptionKey []byte, verifyKey ed25519.PublicKey, now time.Time) (Payload, error) {
	return open(envelope, binding, encryptionKey, verifyKey, now, false)
}

func open(envelope Envelope, binding Binding, encryptionKey []byte, verifyKey ed25519.PublicKey, now time.Time, allowExpired bool) (Payload, error) {
	var empty Payload
	header := envelope.Header
	if !binding.Valid() || !validHeader(header) || header.AuthorityID != binding.AuthorityID || header.Epoch != binding.Epoch || header.RecipientID != binding.RecipientID ||
		len(encryptionKey) != 32 || len(verifyKey) != ed25519.PublicKeySize || len(envelope.Ciphertext) > MaxBytes || header.IssuedAt > now.Unix()+60 {
		return empty, ErrInvalid
	}
	signature, errSignature := base64.StdEncoding.Strict().DecodeString(envelope.Signature)
	if errSignature != nil || !ed25519.Verify(verifyKey, signedBytes(envelope), signature) {
		return empty, ErrInvalid
	}
	if !allowExpired && header.ExpiresAt <= now.Unix() {
		return empty, ErrExpired
	}
	block, _ := aes.NewCipher(encryptionKey)
	aead, _ := cipher.NewGCM(block)
	nonce, errNonce := base64.StdEncoding.Strict().DecodeString(envelope.Nonce)
	ciphertext, errCipher := base64.StdEncoding.Strict().DecodeString(envelope.Ciphertext)
	if errNonce != nil || len(nonce) != aead.NonceSize() || errCipher != nil {
		return empty, ErrInvalid
	}
	plain, errOpen := aead.Open(nil, nonce, ciphertext, aad(header))
	if errOpen != nil || Decode(plain, &empty) != nil || !validSettings(empty.Settings) {
		return Payload{}, ErrInvalid
	}
	return cleanPayload(empty, now, time.Unix(header.ExpiresAt, 0))
}

func cleanPayload(payload Payload, now, lease time.Time) (Payload, error) {
	if len(payload.Accounts) > MaxAccounts {
		return Payload{}, ErrInvalid
	}
	result := Payload{Settings: payload.Settings, Accounts: make([]Account, 0, len(payload.Accounts))}
	seen := make(map[string]bool)
	for _, account := range payload.Accounts {
		if !ValidAccountName(account.Name) || seen[account.Name] {
			return Payload{}, ErrInvalid
		}
		seen[account.Name] = true
		credential, eligible, errClean := ServingCredential(account.Credential, now, lease)
		if errClean != nil {
			return Payload{}, errClean
		}
		if eligible {
			result.Accounts = append(result.Accounts, Account{Name: account.Name, Credential: credential})
		}
	}
	return result, nil
}

func stripRefresh(value any) any {
	switch object := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(object))
		for name, child := range object {
			key := strings.ToLower(strings.Map(func(r rune) rune {
				if r == '_' || r == '-' || r == ' ' {
					return -1
				}
				return r
			}, name))
			if strings.Contains(key, "refresh") || key == "idtoken" || key == "apikey" || key == "clientsecret" || key == "clientassertion" || key == "privatekey" || key == "password" {
				continue
			}
			result[name] = stripRefresh(child)
		}
		return result
	case []any:
		result := make([]any, len(object))
		for index, child := range object {
			result[index] = stripRefresh(child)
		}
		return result
	default:
		return value
	}
}

// ServingCredential revalidates on both sides, strips nested refresh material
// and applies a mandatory serving lease. Unknown token expiry stays excluded.
func ServingCredential(raw []byte, now, lease time.Time) (json.RawMessage, bool, error) {
	var source map[string]any
	if len(raw) > 256*1024 || json.Unmarshal(raw, &source) != nil || source == nil {
		return nil, false, ErrInvalid
	}
	provider, _ := source["type"].(string)
	if provider != "claude" && provider != "codex" && provider != "xai" {
		return nil, false, ErrInvalid
	}
	if kind, exists := source["auth_kind"]; exists && kind != "oauth" {
		return nil, false, ErrInvalid
	}
	if source["disabled"] == true || source["requires_login"] == true {
		return nil, false, nil
	}
	access, _ := source["access_token"].(string)
	expiry, _ := source["expired"].(string)
	if expiry == "" {
		expiry, _ = source["expire"].(string)
	}
	if expiry == "" {
		expiry, _ = source["expires_at"].(string)
	}
	expiresAt, errExpiry := time.Parse(time.RFC3339Nano, expiry)
	if access == "" || errExpiry != nil || !expiresAt.After(now) {
		return nil, false, nil
	}
	if expiresAt.Before(lease) {
		lease = expiresAt
	}
	cleaned := stripRefresh(source).(map[string]any)
	cleaned["auth_kind"] = "oauth"
	cleaned["refresh_disabled"] = true
	cleaned["prism_serving_expires_at"] = lease.UTC().Format(time.RFC3339Nano)
	encoded, errEncode := json.Marshal(cleaned)
	if errEncode != nil {
		return nil, false, ErrInvalid
	}
	return encoded, true, nil
}
