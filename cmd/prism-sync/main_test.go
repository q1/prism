package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/prismsync"
	"gopkg.in/yaml.v3"
)

func TestReplicaConfigUsesSignedInventoryAndPrivateListener(t *testing.T) {
	receipt := prismsync.Receipt{AuthDir: "/private/generation/auths", Settings: prismsync.Settings{Strategy: "reset-priority", RequestRetry: 2, MaxRetryInterval: 30}}
	base := []byte("host: 127.0.0.1\nport: 19191\nauth-dir: /ignored\napi-keys: [fixture-serving-key]\nremote-management:\n  secret-key: fixture-management-key\n")
	encoded, errConfig := replicaConfig(base, receipt)
	if errConfig != nil {
		t.Fatal(errConfig)
	}
	var config map[string]any
	_ = yaml.Unmarshal(encoded, &config)
	if config["auth-dir"] != receipt.AuthDir || config["prism-replica"] != true || config["save-cooldown-status"] != false {
		t.Fatal("replica authority not enforced")
	}
	routing := config["routing"].(map[string]any)
	if routing["prism-policy"] != true || routing["strategy"] != "reset-priority" {
		t.Fatal("signed policy not applied")
	}
	for _, rejected := range []string{"host: 0.0.0.0\n", "host: 8.8.8.8\n", "host: 127.0.0.1\nclaude-api-key: [fixture]\n", "host: 127.0.0.1\nplugins: {enabled: true}\n"} {
		if _, errRejected := replicaConfig([]byte(rejected), receipt); errRejected == nil {
			t.Fatal("base config admitted a public listener or extra provider authority")
		}
	}
}

func TestExplicitCLIKeygenAndPrimaryExportNoCredentialOutput(t *testing.T) {
	directory := t.TempDir()
	_ = os.Chmod(directory, 0o700)
	var output bytes.Buffer
	if errRun := run([]string{"keygen", "--directory", directory}, &output); errRun != nil {
		t.Fatal(errRun)
	}
	var generated struct {
		Epoch string `json:"epoch"`
	}
	if json.Unmarshal(output.Bytes(), &generated) != nil || len(generated.Epoch) != 32 {
		t.Fatal("key creation receipt invalid")
	}
	if bytes.Contains(output.Bytes(), []byte("PRIVATE")) {
		t.Fatal("key material printed")
	}
	if errRun := run([]string{"keygen", "--directory", directory}, &output); errRun == nil {
		t.Fatal("key generation replaced existing trust")
	}
}

func TestSupervisorRefusesMissingOrExpiredJournalWithoutLaunching(t *testing.T) {
	directory := t.TempDir()
	_ = os.Chmod(directory, 0o700)
	base := filepath.Join(directory, "base.yaml")
	_ = os.WriteFile(base, []byte("host: 127.0.0.1\n"), 0o600)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Second))
	defer cancel()
	if errServe := supervise(ctx, prismsync.ReceiverConfig{StateDir: directory}, base, "/nonexistent-engine"); errServe == nil {
		t.Fatal("supervisor launched without validated serving state")
	}
}

type fixtureServingProcess struct {
	done    chan error
	once    sync.Once
	stopped chan struct{}
}

func (process *fixtureServingProcess) finished() <-chan error { return process.done }
func (process *fixtureServingProcess) stop() {
	process.once.Do(func() { close(process.stopped); close(process.done) })
}

func TestSupervisorPublishesFullGenerationAndStopsAtLeaseExpiry(t *testing.T) {
	now := time.Unix(1800000000, 0)
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	verify, signing, _ := ed25519.GenerateKey(rand.Reader)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	keyFile, verifyFile := filepath.Join(dir, "recipient.key"), filepath.Join(dir, "verify.key")
	_ = os.WriteFile(keyFile, key, 0o600)
	_ = os.WriteFile(verifyFile, verify, 0o600)
	binding := prismsync.Binding{AuthorityID: "primary", Epoch: "00000000000000000000000000000001", RecipientID: "replica"}
	config := prismsync.ReceiverConfig{Schema: "prism-serving-receiver/v1", Binding: binding, StateDir: dir, KeyFile: keyFile, VerifyKeyFile: verifyFile}
	header := prismsync.Header{Schema: prismsync.Schema, AuthorityID: binding.AuthorityID, Epoch: binding.Epoch, RecipientID: binding.RecipientID, Generation: 1, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix()}
	payload := prismsync.Payload{Settings: prismsync.Settings{Strategy: "reset-priority"}, Accounts: []prismsync.Account{}}
	envelope, _ := prismsync.Seal(header, payload, key, signing)
	if _, errImport := prismsync.Import(config, envelope, now); errImport != nil {
		t.Fatal(errImport)
	}
	ticks := make(chan time.Time)
	starts := make(chan *fixtureServingProcess, 2)
	result := make(chan error, 1)
	go func() {
		result <- superviseGenerations(context.Background(), config, ticks, func() time.Time { return now }, func(receipt prismsync.Receipt) (servingProcess, error) {
			process := &fixtureServingProcess{done: make(chan error), stopped: make(chan struct{})}
			starts <- process
			return process, nil
		})
	}()
	first := <-starts
	header.Generation++
	payload.Settings.Strategy = "fill-first"
	envelope, _ = prismsync.Seal(header, payload, key, signing)
	if _, errImport := prismsync.Import(config, envelope, now); errImport != nil {
		t.Fatal(errImport)
	}
	ticks <- now.Add(time.Second)
	second := <-starts
	select {
	case <-first.stopped:
	default:
		t.Fatal("new inventory started before old generation was fenced")
	}
	ticks <- now.Add(time.Minute)
	if errResult := <-result; errResult != prismsync.ErrExpired {
		t.Fatal("lease expiry did not terminate supervisor")
	}
	select {
	case <-second.stopped:
	default:
		t.Fatal("expired generation kept running")
	}
}

type fixtureRenewableProcess struct {
	fixtureServingProcess
	renewed chan prismsync.Receipt
}

func (process *fixtureRenewableProcess) renew(receipt prismsync.Receipt) error {
	process.renewed <- receipt
	return nil
}

func TestSupervisorRenewsUnchangedInventoryWithoutInterruptingStreams(t *testing.T) {
	now := time.Unix(1800000000, 0)
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	verify, signing, _ := ed25519.GenerateKey(rand.Reader)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	keyFile, verifyFile := filepath.Join(dir, "recipient.key"), filepath.Join(dir, "verify.key")
	_ = os.WriteFile(keyFile, key, 0o600)
	_ = os.WriteFile(verifyFile, verify, 0o600)
	binding := prismsync.Binding{AuthorityID: "primary", Epoch: "00000000000000000000000000000001", RecipientID: "replica"}
	config := prismsync.ReceiverConfig{Schema: "prism-serving-receiver/v1", Binding: binding, StateDir: dir, KeyFile: keyFile, VerifyKeyFile: verifyFile}
	header := prismsync.Header{Schema: prismsync.Schema, AuthorityID: binding.AuthorityID, Epoch: binding.Epoch, RecipientID: binding.RecipientID, Generation: 1, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix()}
	payload := prismsync.Payload{Settings: prismsync.Settings{Strategy: "reset-priority"}, Accounts: []prismsync.Account{}}
	envelope, _ := prismsync.Seal(header, payload, key, signing)
	if _, errImport := prismsync.Import(config, envelope, now); errImport != nil {
		t.Fatal(errImport)
	}
	ticks := make(chan time.Time)
	starts := make(chan *fixtureRenewableProcess, 2)
	result := make(chan error, 1)
	go func() {
		result <- superviseGenerations(context.Background(), config, ticks, func() time.Time { return now }, func(receipt prismsync.Receipt) (servingProcess, error) {
			process := &fixtureRenewableProcess{fixtureServingProcess: fixtureServingProcess{done: make(chan error), stopped: make(chan struct{})}, renewed: make(chan prismsync.Receipt, 1)}
			starts <- process
			return process, nil
		})
	}()
	first := <-starts
	header.Generation++
	header.IssuedAt += 30
	header.ExpiresAt += 60
	envelope, _ = prismsync.Seal(header, payload, key, signing)
	if _, errImport := prismsync.Import(config, envelope, now.Add(30*time.Second)); errImport != nil {
		t.Fatal(errImport)
	}
	ticks <- now.Add(30 * time.Second)
	if receipt := <-first.renewed; receipt.Generation != 2 {
		t.Fatal("new lease not acknowledged")
	}
	select {
	case <-first.stopped:
		t.Fatal("same inventory renewal interrupted active streams")
	default:
	}
	select {
	case <-starts:
		t.Fatal("lease renewal launched a replacement process")
	default:
	}
	// A policy change still fences the entire prior inventory before starting.
	header.Generation++
	payload.Settings.Strategy = "fill-first"
	envelope, _ = prismsync.Seal(header, payload, key, signing)
	if _, errImport := prismsync.Import(config, envelope, now.Add(40*time.Second)); errImport != nil {
		t.Fatal(errImport)
	}
	ticks <- now.Add(40 * time.Second)
	second := <-starts
	select {
	case <-first.stopped:
	default:
		t.Fatal("changed policy did not fence old inventory")
	}
	ticks <- now.Add(2 * time.Minute)
	if errResult := <-result; errResult != prismsync.ErrExpired {
		t.Fatal("renewed lease did not expire")
	}
	select {
	case <-second.stopped:
	default:
		t.Fatal("expired renewed process remained active")
	}
}
