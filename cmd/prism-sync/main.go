// prism-sync is an explicit private-file transport and replica supervisor.
// It never opens a listener or reads q1code configuration.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/prismsync"
	"gopkg.in/yaml.v3"
)

func main() {
	if errRun := run(os.Args[1:], os.Stdout); errRun != nil {
		// Never print filesystem/parser/child diagnostics: they can contain
		// account identifiers, provider credentials or a private config value.
		fmt.Fprintln(os.Stderr, "Prism sync failed; verify private configuration, recipient admission, generation fence and lease.")
		os.Exit(1)
	}
}

func run(args []string, output io.Writer) error {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
		_, errWrite := fmt.Fprintln(output, "Usage: prism-sync <keygen|export|import|verify|serve> [options]\nOptions: --config FILE --input FILE --output FILE --recipient ID --directory DIR --base-config FILE --engine FILE\nAll credential and key paths must name private files. Enrollment and service activation are explicit operator actions.")
		return errWrite
	}
	if len(args) == 0 {
		return prismsync.ErrInvalid
	}
	flags := flag.NewFlagSet("prism-sync", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "Private primary or receiver JSON config")
	inputPath := flags.String("input", "", "Encrypted bundle input")
	outputPath := flags.String("output", "", "New encrypted bundle output")
	recipient := flags.String("recipient", "", "Enrolled recipient identity")
	directory := flags.String("directory", "", "Existing private key directory")
	baseConfig := flags.String("base-config", "", "Private transport-only engine config")
	engine := flags.String("engine", "", "Absolute local Prism engine executable")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return prismsync.ErrInvalid
	}
	now := time.Now().UTC()
	switch args[0] {
	case "keygen":
		epoch, errKeys := prismsync.GenerateKeys(*directory)
		if errKeys != nil {
			return errKeys
		}
		return json.NewEncoder(output).Encode(map[string]any{"result": "created", "epoch": epoch})
	case "export":
		primaryBytes, errPrimaryRead := prismsync.PrivateRead(*configPath, 128*1024)
		if errPrimaryRead != nil {
			return errPrimaryRead
		}
		config, errConfig := prismsync.LoadPrimary(*configPath)
		if errConfig != nil {
			return errConfig
		}
		settings, engineBytes, errSettings := primarySettings(config.EngineConfigFile)
		if errSettings != nil {
			return errSettings
		}
		envelope, errExport := prismsync.Export(config, *recipient, settings, now)
		if errExport != nil {
			return errExport
		}
		// An engine config change during the snapshot invalidates this export.
		latest, errRead := prismsync.PrivateRead(config.EngineConfigFile, 2*1024*1024)
		if errRead != nil || !bytes.Equal(engineBytes, latest) {
			return prismsync.ErrUnavailable
		}
		currentPrimary, errReadPrimary := prismsync.PrivateRead(*configPath, 128*1024)
		if errReadPrimary != nil || !bytes.Equal(primaryBytes, currentPrimary) {
			return prismsync.ErrUnavailable
		}
		data, errEncode := json.Marshal(envelope)
		if errEncode != nil || prismsync.WriteNew(*outputPath, data) != nil {
			return prismsync.ErrUnavailable
		}
		return json.NewEncoder(output).Encode(map[string]any{"result": "exported", "generation": envelope.Header.Generation, "expiresAt": envelope.Header.ExpiresAt, "digest": prismsync.Digest(envelope)})
	case "import", "verify":
		config, errConfig := prismsync.LoadReceiver(*configPath)
		if errConfig != nil {
			return errConfig
		}
		var receipt prismsync.Receipt
		var errReceipt error
		if args[0] == "import" {
			data, errRead := prismsync.PrivateRead(*inputPath, prismsync.MaxBytes)
			var envelope prismsync.Envelope
			if errRead != nil || prismsync.Decode(data, &envelope) != nil {
				return prismsync.ErrInvalid
			}
			receipt, errReceipt = prismsync.Import(config, envelope, now)
		} else {
			receipt, errReceipt = prismsync.Current(config, now)
		}
		if errReceipt != nil {
			return errReceipt
		}
		receipt.AuthDir = ""
		return json.NewEncoder(output).Encode(receipt)
	case "serve":
		config, errConfig := prismsync.LoadReceiver(*configPath)
		if errConfig != nil {
			return errConfig
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		return supervise(ctx, config, *baseConfig, *engine)
	default:
		return prismsync.ErrInvalid
	}
}

func primarySettings(path string) (prismsync.Settings, []byte, error) {
	data, errRead := prismsync.PrivateRead(path, 2*1024*1024)
	if errRead != nil {
		return prismsync.Settings{}, nil, errRead
	}
	var config struct {
		Routing struct {
			Strategy        string `yaml:"strategy"`
			SessionAffinity bool   `yaml:"session-affinity"`
		} `yaml:"routing"`
		RequestRetry     int `yaml:"request-retry"`
		MaxRetryInterval int `yaml:"max-retry-interval"`
	}
	if yaml.Unmarshal(data, &config) != nil {
		return prismsync.Settings{}, nil, prismsync.ErrInvalid
	}
	if config.Routing.Strategy == "" {
		config.Routing.Strategy = "round-robin"
	}
	return prismsync.Settings{Strategy: config.Routing.Strategy, SessionAffinity: config.Routing.SessionAffinity,
		RequestRetry: config.RequestRetry, MaxRetryInterval: config.MaxRetryInterval}, data, nil
}

func privateListener(host string) bool {
	if host == "localhost" {
		return true
	}
	address, errParse := netip.ParseAddr(host)
	return errParse == nil && (address.IsLoopback() || address.IsPrivate() || netip.MustParsePrefix("100.64.0.0/10").Contains(address))
}

func replicaConfig(base []byte, receipt prismsync.Receipt) ([]byte, error) {
	var config map[string]any
	if yaml.Unmarshal(base, &config) != nil || config == nil {
		return nil, prismsync.ErrInvalid
	}
	host, _ := config["host"].(string)
	if !privateListener(host) {
		return nil, prismsync.ErrInvalid
	}
	// A recipient's transport file cannot add a second authority or provider
	// pool. Only the signed account inventory may supply serving credentials.
	for _, field := range []string{"gemini-api-key", "interactions-api-key", "codex-api-key", "xai-api-key", "claude-api-key", "vertex-api-key", "openai-compatibility", "ampcode", "plugins", "home"} {
		if value, exists := config[field]; exists && value != nil {
			return nil, prismsync.ErrInvalid
		}
	}
	config["auth-dir"] = receipt.AuthDir
	config["prism-replica"] = true
	config["routing"] = map[string]any{"prism-policy": true, "strategy": receipt.Settings.Strategy, "session-affinity": receipt.Settings.SessionAffinity}
	config["request-retry"], config["max-retry-interval"] = receipt.Settings.RequestRetry, receipt.Settings.MaxRetryInterval
	config["save-cooldown-status"] = false
	config["pprof"] = map[string]any{"enable": false}
	config["plugins"] = map[string]any{"enabled": false}
	encoded, errEncode := yaml.Marshal(config)
	if errEncode != nil {
		return nil, prismsync.ErrInvalid
	}
	return encoded, nil
}

type engineChild struct {
	command   *exec.Cmd
	done      chan error
	directory string
	authDir   string
}

type servingProcess interface {
	finished() <-chan error
	stop()
}

func (child *engineChild) finished() <-chan error { return child.done }

func launch(engine string, config prismsync.ReceiverConfig, base []byte, receipt prismsync.Receipt) (*engineChild, error) {
	if !filepath.IsAbs(engine) {
		return nil, prismsync.ErrInvalid
	}
	directory, errTemp := os.MkdirTemp(config.StateDir, ".runtime-")
	if errTemp != nil {
		return nil, prismsync.ErrUnavailable
	}
	authDir := filepath.Join(directory, "auths")
	if os.Mkdir(authDir, 0o700) != nil || prismsync.MaterializeRuntime(receipt, authDir) != nil {
		_ = os.RemoveAll(directory)
		return nil, prismsync.ErrUnavailable
	}
	runtimeReceipt := receipt
	runtimeReceipt.AuthDir = authDir
	encoded, errConfig := replicaConfig(base, runtimeReceipt)
	if errConfig != nil {
		_ = os.RemoveAll(directory)
		return nil, errConfig
	}
	path := filepath.Join(directory, "config.yaml")
	if prismsync.WriteNew(path, encoded) != nil {
		_ = os.RemoveAll(directory)
		return nil, prismsync.ErrUnavailable
	}
	command := exec.Command(engine, "--config", path, "--local-model")
	// Never inherit optional alternate storage credentials: replicas must read
	// only their signed file inventory. Logs remain owned by the engine process.
	for _, entry := range os.Environ() {
		name := strings.ToUpper(strings.SplitN(entry, "=", 2)[0])
		if strings.HasPrefix(name, "PGSTORE_") || strings.HasPrefix(name, "GITSTORE_") || strings.HasPrefix(name, "OBJECTSTORE_") || strings.HasPrefix(name, "HOME_") || name == "MANAGEMENT_PASSWORD" {
			continue
		}
		command.Env = append(command.Env, entry)
	}
	command.Dir = directory
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	if command.Start() != nil {
		_ = os.RemoveAll(directory)
		return nil, prismsync.ErrUnavailable
	}
	child := &engineChild{command: command, done: make(chan error, 1), directory: directory, authDir: authDir}
	go func() { child.done <- command.Wait(); close(child.done) }()
	return child, nil
}

func (child *engineChild) renew(receipt prismsync.Receipt) error {
	return prismsync.MaterializeRuntime(receipt, child.authDir)
}

func (child *engineChild) stop() {
	if child == nil {
		return
	}
	_ = child.command.Process.Signal(syscall.SIGTERM)
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-child.done:
	case <-timer.C:
		_ = child.command.Process.Kill()
		<-child.done
	}
	_ = os.RemoveAll(child.directory)
}

// supervise renews identical signed inventory without replacing active streams.
// Changed credentials, settings or inventory stop the old child first. Lease
// expiry stops the process even when the primary or transport is unreachable.
func supervise(ctx context.Context, config prismsync.ReceiverConfig, basePath, engine string) error {
	base, errBase := prismsync.PrivateRead(basePath, 2*1024*1024)
	if errBase != nil {
		return errBase
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	return superviseGenerations(ctx, config, ticker.C, time.Now, func(receipt prismsync.Receipt) (servingProcess, error) {
		return launch(engine, config, base, receipt)
	})
}

func superviseGenerations(ctx context.Context, config prismsync.ReceiverConfig, ticks <-chan time.Time, now func() time.Time,
	start func(prismsync.Receipt) (servingProcess, error)) error {
	active, errCurrent := prismsync.Current(config, now())
	if errCurrent != nil {
		return errCurrent
	}
	child, errLaunch := start(active)
	if errLaunch != nil {
		return errLaunch
	}
	defer func() {
		if child != nil {
			child.stop()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-child.finished():
			return prismsync.ErrUnavailable
		case tick := <-ticks:
			if tick.Unix() >= active.ExpiresAt {
				return prismsync.ErrExpired
			}
			latest, errRead := prismsync.Current(config, tick)
			if errors.Is(errRead, prismsync.ErrBusy) {
				continue
			}
			if errRead != nil {
				return errRead
			}
			if latest.Generation < active.Generation || (latest.Generation == active.Generation && latest.Digest != active.Digest) {
				return prismsync.ErrReplay
			}
			if latest.AuthDir == active.AuthDir {
				continue
			}
			if latest.ContentDigest != "" && latest.ContentDigest == active.ContentDigest {
				if renewable, ok := child.(interface{ renew(prismsync.Receipt) error }); ok {
					if errRenew := renewable.renew(latest); errRenew != nil {
						return errRenew
					}
					active = latest
					continue
				}
			}
			child.stop()
			child, errLaunch = start(latest)
			if errLaunch != nil {
				return errLaunch
			}
			active = latest
		}
	}
}
