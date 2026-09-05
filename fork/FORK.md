# Prism engine fork

The optional [serving snapshot contract](docs/prism-serving-sync.md) defines
Prism-native encrypted replica distribution and its explicit activation gates.

Prism is a maintained fork of router-for-me/CLIProxyAPI. Keep the upstream Go module path, command name, management protocol, and all upstream providers, including Grok, compatible. Prism owns account and routing authority; q1/q1code supplies an integrated management client. Private placement, secrets, and Cloudflare configuration live in mic.sc.

`main` is a fast-forward-only upstream mirror. `prism` is the reviewed customization series based on the upstream release in `fork/upstream.json`. Keep generic fixes independently cherry-pickable and label commit trailers `Upstream: candidate`; integration-only changes use `Upstream: no`. Do not open upstream PRs without the owner's request.

## Updating upstream

Start from a clean `prism` checkout. Fetch upstream tags, fast-forward the mirror, and snapshot the current customization tip before rebasing a new `sync/<timestamp>` branch onto the chosen release tag. Preserve `prism` during the rebase (`--no-update-refs`). Never resolve an upstream file wholesale with ours/theirs. Drop changes upstream has absorbed, compare both series with `git range-diff`, and update the recorded upstream release.

Run focused tests for changed behavior and compile `./cmd/server`. Push the sync branch for Prism CI. Promote only after reviewing conflicts and green CI on that exact head, using an explicit force-with-lease on the previous remote `prism` tip. Updating source does not deploy or rotate credentials.

## Credentials

Use the upstream auth store and refresh machinery as the baseline. Publish lifecycle observations through authenticated management APIs without exposing access or refresh tokens. Cross-machine refresh ownership must be coordinated before replicated credentials are allowed to renew independently. Never infer that a timestamp-based file merge is a refresh lock.

Existing upstream workflows stay unmodified. Prism CI runs on the customization and sync branches; release publication and deployments are separate actions.

## Subscription routing

Fleet installations enable `routing.prism-policy: true` so selecting a balancing
strategy cannot bypass the pool's freshness and reserve policy. `reset-priority`
also enables that policy; existing upstream installations retain their behavior
until they opt in. Model availability uses the same effective policy as request
selection. Claude and Codex subscription accounts require fresh applicable
windows; Grok and API-key accounts keep their native eligibility constraints.

The initial observation lifetime is fifteen minutes. Missing, expired-reset or
older observations exclude an account; a reset timestamp never supplies an
invented fresh allowance. A reserve defaults to 3% per applicable window;
`reserve_percent: null` disables it. Reserves are soft selection thresholds,
not token reservations, and do not cancel an admitted stream. Fable-only limits
and reserves never exclude non-Fable requests.

Reset priority anchors its thirty-minute candidate bucket to the earliest
five-hour reset. Within that bucket it accounts for requests whose contexts are
still active, then favors remaining weekly allowance per hour before reset
within a known equal-plan cohort. Fable requests use their Fable weekly window;
the overall weekly window remains an independent eligibility gate. Unknown or
mixed plans rotate instead of equating their quota percentages. This scoring
rule is an initial implementation of the accepted scenarios, not a measured
capacity estimate or a guarantee of optimal allocation. Context-lifetime counts
are conservative during retries and represent active work rather than tokens.

The owning manager checks stale accounts through the provider's usage endpoint,
using the existing serialized OAuth refresh mechanism only when credentials
need recovery. If usage stays unknown, it can send one small synthetic inference
request per account per hour, with sixteen requested output tokens and no tools.
Failed checks back off from two minutes to at most sixty-four minutes. A success
without usable quota remains excluded. Persistent inference authentication
failure requires sign-in; serving-only replicas perform usage observation only,
without OAuth refresh or synthetic inference probes.
These provider endpoint and output-bound assumptions still need real-account
qualification for each supported subscription; fixture tests alone do not prove
provider compatibility.

`GET /v0/management/prism/models` supplies model-specific availability, usable
account counts and safe warnings without account identities. Disabling the last
account keeps its models visible as unavailable. Claude, Codex and Grok disabled
accounts use the same local plan, exclusion, alias and prefix mapping on cold
start. Previously observed dynamic models can remain visible, but an account
must be actively registered for any model to count as usable; removed accounts
contribute no models. Administrative
auth-file reads include normalized quota windows and the reserve setting;
`PATCH /v0/management/auth-files/fields` accepts a finite `reserve_percent` from
0 to 100 or null. Locally declined pool requests distinguish reserve avoidance,
provider exhaustion and unknown availability and forbid direct fallback.


## Versioned panel administration

The identity-protected panel supplies actor, operation ID and expected revision
headers. Configuration setters validate against an isolated private candidate,
then recheck the complete configuration and account-policy revision under commit
locks before publishing. Account owner-field edits merge into the latest token
state. Credential files use private staging, file synchronization and atomic
rename; failed preparation cannot truncate the authoritative file.

Panel import accepts one JSON credential file per operation, up to 256 KiB.
Successful import registers a fresh epoch so pending refresh work cannot replace
it. Bulk UI wrappers execute single-file import/removal operations sequentially
with fresh revisions; the legacy all-files and multi-file wire operations remain
unsupported. Each successful write returns its actual revision and operation ID.

Changing host wiring, engine admission/management keys, eligibility authority or
plugin execution remains a trusted local operator action. Protected panel plugin
installation/runtime mutation and Vertex credential issuance return an explicit
`requires_operator` conflict. Trusted loopback upstream management remains
available to the operator. Settings revisions include host wiring and all exposed
owner metadata, but never expose their values or change merely for token refresh
and quota observations.
