# Prism serving snapshots

Prism owns this optional distribution path independently of q1code. Most remote
environments should call the primary's admitted inference API and receive no
provider credentials. Enroll a serving replica only when its local execution is
required. The v1 transport is an explicitly invoked private file transfer over
the fleet's verified SSH connection; it opens no listener or public export route.

## Authority and wire contract

`cmd/prism-sync` exports a complete authoritative inventory for one recipient.
Each recipient has an independent 32-byte AES key and an explicit account scope.
The primary encrypts the full inventory with AES-256-GCM and signs the envelope
with Ed25519. The authenticated header binds the schema, primary identity,
authority epoch, recipient identity, monotonically increasing generation and
lease interval. Account filenames, metadata and serving tokens are encrypted.

The receiver pins the primary identity, 32-character hexadecimal epoch, Ed25519
verification key and its own recipient identity. It rejects another identity,
wrong key, tampering, a future-issued envelope beyond a 60-second clock allowance,
an expired lease, a lower generation, or different contents at the same
generation. An exact repeat is idempotent. Synchronize fleet clocks.

The encrypted `accepted.json` is also the durable receiver generation fence.
The primary persists `primary-generation.json` before returning an export.
Neither generation is inferred from filesystem modification times. Full snapshots
apply removals without tombstone expiry or a bidirectional merge. A receiver
never sends accounts back to the primary.

Snapshots contain the four supported shared inference settings: balancing
strategy, session affinity, request retry count and maximum retry interval.
Account files retain their explicit weights, reserves, exclusions and aliases.
The receiver's private base config supplies transport, local serving keys and
management credentials; it cannot add API-key accounts or plugins. Other global
provider settings are not replicated by this contract.

## Serving projection and lease

Only Claude, Codex and xAI OAuth files are supported. Disabled, sign-in-required,
expired or unknown-expiry accounts are omitted. Each side recursively strips
fields containing refresh material, ID tokens and private token-exchange fields.
It forces `refresh_disabled: true` and sets `prism_serving_expires_at` to the
earlier of the signed lease and provider token expiry. No receiver owns OAuth
refresh. Native routing enforces this lease across balancing strategies.

Claude and Codex replicas begin with quota availability unknown. The worker may
read the provider's usage endpoint using the serving token, but cannot refresh
tokens or issue synthetic inference probes. Fresh observed windows are required
before ordinary requests become eligible. Grok retains native eligibility.
Unknown quota never becomes healthy merely because a model appears in a list.

Use a 900-second lease and transfer more frequently than the lease. The supported
range is 60 seconds to 24 hours; increasing it also increases the maximum offline
revocation delay. Setting a recipient's `enabled` to `false` stops new exports.
Removing an account from its scope or the primary removes it in the next full
snapshot. Already distributed provider access tokens cannot be cryptographically
retracted from a malicious recipient; the fleet replica enforces expiry, and a
provider-side revocation remains the way to invalidate the underlying token.

## Private configuration

Build both binaries with the repository's pinned Go toolchain:

```sh
go build -o /private/build/prism ./cmd/server
go build -o /private/build/prism-sync ./cmd/prism-sync
```

All config, key, bundle and state paths are absolute and canonical, without
symlink ancestors. Directories must be owned by the invoking user and mode 0700;
files must be owned by that user, mode 0600, regular and not hard-linked. Create
fresh private directories at the machine action gate. Never pass key values on
the command line or copy them into Git.

Run `prism-sync keygen --directory /private/enrollment` once in a new private
directory. It writes raw `primary-signing.key`, `primary-verify.key` and
`recipient.key`; output contains only a creation receipt and the generated
authority epoch. Keep the signing key only on the primary. Privately provision
the recipient key on those two enrolled machines and the verification key on the
recipient. Generate separate random recipient keys for additional recipients;
never reuse another recipient's key. No enrollment is implicit.

Primary config (replace the epoch and paths; the JSON contains key-file names,
never key values):

```json
{
  "schema": "prism-serving-primary/v1",
  "authorityId": "michael-pc-ubuntu",
  "epoch": "REPLACE_WITH_GENERATED_32_HEX_EPOCH",
  "stateDir": "/private/prism-sync-primary",
  "authDir": "/private/prism-auths",
  "engineConfigFile": "/private/prism-engine.yaml",
  "signingKeyFile": "/private/enrollment/primary-signing.key",
  "recipients": [
    {
      "id": "spark-01",
      "enabled": true,
      "keyFile": "/private/enrollment/recipient.key",
      "accounts": ["claude-account.json", "codex-account.json"],
      "leaseSeconds": 900
    }
  ]
}
```

An explicit `"accounts": ["*"]` scopes all supported account files in that
primary directory. Prefer named accounts when unrelated providers share it.
An empty scope exports an empty authoritative inventory.

Receiver config:

```json
{
  "schema": "prism-serving-receiver/v1",
  "authorityId": "michael-pc-ubuntu",
  "epoch": "REPLACE_WITH_THE_SAME_32_HEX_EPOCH",
  "recipientId": "spark-01",
  "stateDir": "/private/prism-sync-receiver",
  "keyFile": "/private/enrollment/recipient.key",
  "verifyKeyFile": "/private/enrollment/primary-verify.key"
}
```

The receiver base YAML must bind an explicit loopback, private LAN or tailnet IP,
and contain only its approved local transport settings and private service keys.
The supervisor sets `auth-dir`, `prism-replica`, mandatory Prism eligibility and
the signed settings. It disables plugins, profiling and cooldown-file writes,
and removes inherited alternate-store/Home environment overrides. A clean
working directory prevents accidental `.env` loading.

## Explicit transfer and activation

```sh
prism-sync export --config /private/primary.json --recipient spark-01 --output /private/new.bundle
```

Transfer `new.bundle` through the existing verified SSH channel to the receiver's
private inbox, then invoke:

```sh
prism-sync import --config /private/receiver.json --input /private/inbox/new.bundle
prism-sync verify --config /private/receiver.json
```

Export/import/verify output is a safe receipt; it never includes account names,
keys or tokens. An output path must be new. Key generation, enrollment, replica
activation, scheduled transfer and production service changes remain explicit
owner action gates. There is no automatic cross-host transfer in the engine.

At the approved activation gate, run the replica through its supervisor:

```sh
prism-sync serve --config /private/receiver.json --base-config /private/replica-transport.yaml --engine /private/build/prism
```

Import stages all account files and settings in a fresh immutable generation,
fsyncs them, commits the encrypted journal and atomically switches `current`.
Startup validates the journal and repairs a crash between journal and pointer
publication. Provider expiry can materialize a smaller inventory without
rewriting any prior generation. Engine request preparation cannot persist into
leased account files; both versioned and legacy administration are read-only.

The supervisor checks for accepted inventory changes once per second. An
unchanged inventory with only a renewed serving lease updates private runtime
copies of the signed account files. The existing file watcher applies the new
lease without replacing the process or interrupting streams. The content digest
includes all credentials, provider token expirations, owner policy and settings;
only the serving lease expiration is excluded. Source content is verified before
runtime publication, and a failed renewal stops the process.

For changed credentials, policy, settings or inventory, it stops
the old engine before launching the new complete inventory and settings,
terminating active streams as part of removal/revocation. Graceful termination
has a five-second bound before the child is killed. This is an explicit process
replacement with a brief availability gap; it does not rely on directory
watchers noticing a swapped symlink. At lease expiry the supervisor stops the
engine. A stale or corrupt journal fails closed. Existing private immutable
directories remain retained; they are not an authorized rollback source.

Do not start a replica directly against an old generation. The supervisor is the
supported runtime entry point. A serving-only replica cannot take refresh
authority during a primary outage. Follow the separately gated fenced recovery
runbook for PC-to-Spark takeover and return.

## Crash and recovery rules

An `.operation-lock` serializes each store. A crashed process may leave it behind;
the lock is never automatically stolen. Inspect and fence all sync processes
before removing that specific stale lock at the machine action gate. A skipped
sender generation after an interrupted export is harmless.

Retain primary generation state, receiver accepted journals, enrollment config
and key material in the encrypted recovery inventory. Never restore an older
receiver fence or decrease primary generation to make an old bundle acceptable.
If trusted generation history is lost, fence both owners, create a new authority
epoch and explicitly re-enroll receivers into fresh state directories. Replacing
a local trust pin is an owner operation, never something a received bundle does.

Fixture tests cover encryption/signature identity, recursive stripping,
recipient revocation/scope, stale and equal-conflicting replay, full removals,
expiry, crash repair, immutable persistence, replica read-only administration
and deterministic process replacement. Live provider schemas and the fleet SSH
activation path still need explicit qualification before claiming a production
replica is serving.
