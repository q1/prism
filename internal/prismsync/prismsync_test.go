package prismsync

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixtureCredential(now time.Time) []byte {
	data, _ := json.Marshal(map[string]any{"type": "claude", "access_token": "fixture-serving-token", "refresh_token": "fixture-refresh-token",
		"expired": now.Add(time.Hour).Format(time.RFC3339), "reserve_percent": 3, "nested": map[string]any{"refreshToken": "fixture-nested-refresh", "items": []any{map[string]any{"REFRESH-TOKEN": "fixture-array-refresh"}}}})
	return data
}

func fixtureEnvelope(t *testing.T, generation uint64, now time.Time) (Envelope, Binding, []byte, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	verify, signing, errKey := ed25519.GenerateKey(rand.Reader)
	if errKey != nil {
		t.Fatal(errKey)
	}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	binding := Binding{"fixture-primary", "00000000000000000000000000000001", "fixture-replica"}
	header := Header{Schema: Schema, AuthorityID: binding.AuthorityID, Epoch: binding.Epoch, RecipientID: binding.RecipientID, Generation: generation, IssuedAt: now.Unix(), ExpiresAt: now.Add(15 * time.Minute).Unix()}
	envelope, errSeal := Seal(header, Payload{Settings: Settings{Strategy: "reset-priority"}, Accounts: []Account{{"claude-fixture.json", fixtureCredential(now)}}}, key, signing)
	if errSeal != nil {
		t.Fatal(errSeal)
	}
	return envelope, binding, key, verify, signing
}

func TestAuthenticatedEnvelopeAndMandatoryServingPolicy(t *testing.T) {
	now := time.Unix(1800000000, 0)
	envelope, binding, key, verify, _ := fixtureEnvelope(t, 1, now)
	wire, _ := json.Marshal(envelope)
	if bytes.Contains(wire, []byte("fixture-serving-token")) || bytes.Contains(wire, []byte("claude-fixture")) {
		t.Fatal("credential identity leaked outside encryption")
	}
	payload, errOpen := Open(envelope, binding, key, verify, now)
	if errOpen != nil || len(payload.Accounts) != 1 {
		t.Fatal("valid snapshot rejected")
	}
	credential := payload.Accounts[0].Credential
	for _, forbidden := range []string{"fixture-refresh-token", "fixture-nested-refresh", "fixture-array-refresh"} {
		if bytes.Contains(credential, []byte(forbidden)) {
			t.Fatal("refresh material survived serving projection")
		}
	}
	if !bytes.Contains(credential, []byte(`"refresh_disabled":true`)) || !bytes.Contains(credential, []byte(`"prism_serving_expires_at"`)) {
		t.Fatal("replica ownership or lease gate missing")
	}
	tampered := envelope
	tampered.Header.Generation++
	if _, errOpen := Open(tampered, binding, key, verify, now); !errors.Is(errOpen, ErrInvalid) {
		t.Fatal("unsigned generation accepted")
	}
	wrongBinding := binding
	wrongBinding.RecipientID = "other-replica"
	if _, errOpen := Open(envelope, wrongBinding, key, verify, now); errOpen == nil {
		t.Fatal("wrong recipient accepted")
	}
	wrongBinding = binding
	wrongBinding.Epoch = strings.Repeat("f", 32)
	if _, errOpen := Open(envelope, wrongBinding, key, verify, now); errOpen == nil {
		t.Fatal("unapproved authority epoch accepted")
	}
	wrongKey := append([]byte(nil), key...)
	wrongKey[0] ^= 1
	if _, errOpen := Open(envelope, binding, wrongKey, verify, now); errOpen == nil {
		t.Fatal("wrong encryption key accepted")
	}
	if _, errOpen := Open(envelope, binding, key, verify, now.Add(15*time.Minute)); !errors.Is(errOpen, ErrExpired) {
		t.Fatal("expired lease accepted")
	}
}

func TestServingProjectionRejectsAmbiguityAndExpiredAccounts(t *testing.T) {
	now := time.Unix(1800000000, 0)
	for _, raw := range [][]byte{[]byte(`[]`), []byte(`{"type":"unsupported"}`), []byte(`{"type":"claude","access_token":`)} {
		if _, _, errClean := ServingCredential(raw, now, now.Add(time.Minute)); errClean == nil {
			t.Fatal("invalid credential admitted")
		}
	}
	for _, patch := range []map[string]any{{"expired": now.Format(time.RFC3339)}, {"requires_login": true}, {"disabled": true}, {"expired": ""}} {
		var credential map[string]any
		_ = json.Unmarshal(fixtureCredential(now), &credential)
		for key, value := range patch {
			credential[key] = value
		}
		data, _ := json.Marshal(credential)
		if _, eligible, errClean := ServingCredential(data, now, now.Add(time.Minute)); errClean != nil || eligible {
			t.Fatal("unusable credential exported")
		}
	}
	for _, name := range []string{"../escape.json", "nested/path.json", ".hidden.json", "a\\b.json", "a\n.json"} {
		if ValidAccountName(name) {
			t.Fatal("unsafe credential name accepted")
		}
	}
}

func writeFixture(t *testing.T, path string, data []byte) {
	t.Helper()
	if errWrite := os.WriteFile(path, data, 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}
}

func receiverFixture(t *testing.T, binding Binding, key []byte, verify ed25519.PublicKey) ReceiverConfig {
	t.Helper()
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	keyFile, verifyFile := filepath.Join(dir, "recipient.key"), filepath.Join(dir, "primary-verify.key")
	writeFixture(t, keyFile, key)
	writeFixture(t, verifyFile, verify)
	return ReceiverConfig{Schema: "prism-serving-receiver/v1", Binding: binding, StateDir: dir, KeyFile: keyFile, VerifyKeyFile: verifyFile}
}

func TestReceiverGenerationFencingFullRemovalAndCrashRepair(t *testing.T) {
	now := time.Unix(1800000000, 0)
	first, binding, key, verify, signing := fixtureEnvelope(t, 5, now)
	config := receiverFixture(t, binding, key, verify)
	receipt, errImport := Import(config, first, now)
	if errImport != nil || receipt.Generation != 5 || receipt.Accounts != 1 {
		t.Fatal("first snapshot not published")
	}
	if _, errRepeat := Import(config, first, now); errRepeat != nil {
		t.Fatal("exact retry was not idempotent")
	}
	payload, _ := Open(first, binding, key, verify, now)
	conflicting, _ := Seal(first.Header, payload, key, signing)
	if _, errConflict := Import(config, conflicting, now); !errors.Is(errConflict, ErrReplay) {
		t.Fatal("equal generation conflict accepted")
	}
	olderHeader := first.Header
	olderHeader.Generation = 4
	older, _ := Seal(olderHeader, payload, key, signing)
	if _, errOlder := Import(config, older, now); !errors.Is(errOlder, ErrReplay) {
		t.Fatal("older snapshot accepted")
	}
	removedHeader := first.Header
	removedHeader.Generation++
	payload.Accounts = []Account{}
	removed, _ := Seal(removedHeader, payload, key, signing)
	next, errNext := Import(config, removed, now)
	if errNext != nil || next.Accounts != 0 {
		t.Fatal("full snapshot removal failed")
	}
	entries, _ := os.ReadDir(next.AuthDir)
	if len(entries) != 0 {
		t.Fatal("removed credential present in published inventory")
	}
	journal, _ := PrivateRead(filepath.Join(config.StateDir, "accepted.json"), MaxBytes)
	if bytes.Contains(journal, []byte("fixture-serving-token")) {
		t.Fatal("journal stores plaintext credentials")
	}
	// Simulate a crash after the new journal was persisted and before its pointer.
	_ = os.Remove(filepath.Join(config.StateDir, "current"))
	relative, _ := filepath.Rel(config.StateDir, filepath.Dir(receipt.AuthDir))
	_ = os.Symlink(relative, filepath.Join(config.StateDir, "current"))
	repaired, errCurrent := Current(config, now)
	if errCurrent != nil || repaired.Generation != 6 || repaired.AuthDir != next.AuthDir {
		t.Fatal("startup did not repair journal/pointer crash")
	}
	if _, errReplay := Import(config, first, now); !errors.Is(errReplay, ErrReplay) {
		t.Fatal("restart forgot generation fence")
	}
	if _, errExpired := Current(config, now.Add(15*time.Minute)); !errors.Is(errExpired, ErrExpired) {
		t.Fatal("startup accepted expired serving journal")
	}
	// Expiry must not erase generation history and permit an older replay.
	if _, errOlder := Import(config, older, now.Add(time.Minute)); !errors.Is(errOlder, ErrReplay) {
		t.Fatal("lease handling erased the fence")
	}
}

func TestPrimaryDurableGenerationRecipientRevocationAndScope(t *testing.T) {
	now := time.Unix(1800000000, 0)
	_, binding, key, verify, signing := fixtureEnvelope(t, 1, now)
	receiver := receiverFixture(t, binding, key, verify)
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	authDir := filepath.Join(dir, "auths")
	_ = os.Mkdir(authDir, 0o700)
	signingPath := filepath.Join(dir, "signing.key")
	writeFixture(t, signingPath, signing)
	writeFixture(t, filepath.Join(authDir, "allowed.json"), fixtureCredential(now))
	writeFixture(t, filepath.Join(authDir, "excluded.json"), fixtureCredential(now))
	config := PrimaryConfig{Schema: "prism-serving-primary/v1", AuthorityID: binding.AuthorityID, Epoch: binding.Epoch, StateDir: dir, AuthDir: authDir,
		SigningKeyFile: signingPath, Recipients: []Recipient{{ID: binding.RecipientID, Enabled: true, KeyFile: receiver.KeyFile, Accounts: []string{"allowed.json"}, LeaseSeconds: 900}}}
	first, errFirst := Export(config, binding.RecipientID, Settings{Strategy: "reset-priority"}, now)
	second, errSecond := Export(config, binding.RecipientID, Settings{Strategy: "reset-priority"}, now)
	if errFirst != nil || errSecond != nil || first.Header.Generation != 1 || second.Header.Generation != 2 {
		t.Fatal("generation was not durably monotonic")
	}
	payload, errOpen := Open(second, binding, key, verify, now)
	if errOpen != nil || len(payload.Accounts) != 1 || payload.Accounts[0].Name != "allowed.json" {
		t.Fatal("recipient scope was not applied")
	}
	config.Recipients[0].Enabled = false
	if _, errRevoked := Export(config, binding.RecipientID, Settings{Strategy: "reset-priority"}, now); errRevoked == nil {
		t.Fatal("revoked recipient received a new snapshot")
	}
	config.Recipients[0].Enabled = true
	_ = os.WriteFile(filepath.Join(dir, ".operation-lock"), nil, 0o600)
	if _, errBusy := Export(config, binding.RecipientID, Settings{Strategy: "reset-priority"}, now); !errors.Is(errBusy, ErrBusy) {
		t.Fatal("concurrent writer lock ignored")
	}
}

func TestReceiverExcludesTokensExpiringWithinSnapshotLease(t *testing.T) {
	now := time.Unix(1800000000, 0)
	envelope, binding, key, verify, signing := fixtureEnvelope(t, 1, now)
	payload, _ := Open(envelope, binding, key, verify, now)
	var account map[string]any
	_ = json.Unmarshal(payload.Accounts[0].Credential, &account)
	account["expired"] = now.Add(time.Minute).Format(time.RFC3339)
	payload.Accounts[0].Credential, _ = json.Marshal(account)
	envelope, _ = Seal(envelope.Header, payload, key, signing)
	config := receiverFixture(t, binding, key, verify)
	if _, errImport := Import(config, envelope, now); errImport != nil {
		t.Fatal(errImport)
	}
	current, errCurrent := Current(config, now.Add(2*time.Minute))
	if errCurrent != nil || current.Accounts != 0 {
		t.Fatal("expired token was not removed on startup")
	}
}

func TestRuntimeMaterializationAuthenticatesBytesAndSeparatesLeaseRenewal(t *testing.T) {
	now := time.Unix(1800000000, 0)
	first, binding, key, verify, signing := fixtureEnvelope(t, 1, now)
	config := receiverFixture(t, binding, key, verify)
	initial, errImport := Import(config, first, now)
	if errImport != nil {
		t.Fatal(errImport)
	}
	directory := t.TempDir()
	_ = os.Chmod(directory, 0o700)
	if errCopy := MaterializeRuntime(initial, directory); errCopy != nil {
		t.Fatal(errCopy)
	}
	before, _ := PrivateRead(filepath.Join(directory, "claude-fixture.json"), 256*1024)
	header := first.Header
	header.Generation++
	header.IssuedAt += 300
	header.ExpiresAt += 300
	payload := Payload{Settings: Settings{Strategy: "reset-priority"}, Accounts: []Account{{"claude-fixture.json", fixtureCredential(now)}}}
	renewal, _ := Seal(header, payload, key, signing)
	renewed, errRenew := Import(config, renewal, now.Add(5*time.Minute))
	if errRenew != nil || renewed.ContentDigest == "" || renewed.ContentDigest != initial.ContentDigest || renewed.Digest == initial.Digest {
		t.Fatal("same-content lease renewal not classified independently")
	}
	if errCopy := MaterializeRuntime(renewed, directory); errCopy != nil {
		t.Fatal(errCopy)
	}
	after, _ := PrivateRead(filepath.Join(directory, "claude-fixture.json"), 256*1024)
	if bytes.Equal(before, after) || !bytes.Contains(after, []byte(time.Unix(header.ExpiresAt, 0).UTC().Format(time.RFC3339))) {
		t.Fatal("runtime lease not renewed")
	}
	writeFixture(t, filepath.Join(renewed.AuthDir, "claude-fixture.json"), bytes.Replace(after, []byte("fixture-serving-token"), []byte("fixture-tampered-token"), 1))
	if errCopy := MaterializeRuntime(renewed, directory); errCopy == nil {
		t.Fatal("tampered source generation materialized")
	}
	unchanged, _ := PrivateRead(filepath.Join(directory, "claude-fixture.json"), 256*1024)
	if !bytes.Equal(after, unchanged) {
		t.Fatal("failed source verification changed runtime")
	}
	for _, field := range []string{"access_token", "expired", "reserve_percent"} {
		var metadata map[string]any
		_ = json.Unmarshal(fixtureCredential(now), &metadata)
		metadata[field] = "fixture-changed"
		changed, _ := json.Marshal(metadata)
		candidate := Payload{Settings: payload.Settings, Accounts: []Account{{"claude-fixture.json", changed}}}
		if renewalDigest(candidate) == renewalDigest(payload) {
			t.Fatal("credential or policy change misclassified as lease renewal")
		}
	}
}
