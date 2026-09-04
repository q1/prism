# Prism engine fork

Prism is a maintained fork of router-for-me/CLIProxyAPI. Keep the upstream Go module path, command name, management protocol, and all upstream providers, including Grok, compatible. The q1code control plane lives in q1/q1code; private placement, secrets, and Cloudflare configuration live in mic.sc.

`main` is a fast-forward-only upstream mirror. `prism` is the reviewed customization series based on the upstream release in `fork/upstream.json`. Keep generic fixes independently cherry-pickable and label commit trailers `Upstream: candidate`; integration-only changes use `Upstream: no`. Do not open upstream PRs without the owner's request.

## Updating upstream

Start from a clean `prism` checkout. Fetch upstream tags, fast-forward the mirror, and snapshot the current customization tip before rebasing a new `sync/<timestamp>` branch onto the chosen release tag. Preserve `prism` during the rebase (`--no-update-refs`). Never resolve an upstream file wholesale with ours/theirs. Drop changes upstream has absorbed, compare both series with `git range-diff`, and update the recorded upstream release.

Run focused tests for changed behavior and compile `./cmd/server`. Push the sync branch for Prism CI. Promote only after reviewing conflicts and green CI on that exact head, using an explicit force-with-lease on the previous remote `prism` tip. Updating source does not deploy or rotate credentials.

## Credentials

Use the upstream auth store and refresh machinery as the baseline. Publish lifecycle observations through authenticated management APIs without exposing access or refresh tokens. Cross-machine refresh ownership must be coordinated before replicated credentials are allowed to renew independently. Never infer that a timestamp-based file merge is a refresh lock.

Existing upstream workflows stay unmodified. Prism CI runs on the customization and sync branches; release publication and deployments are separate actions.
