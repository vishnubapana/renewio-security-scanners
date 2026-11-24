# renewio-security-scanners

On-demand GitHub Actions security scanning for Renewio IPA sideloads.

This directory is the scanner bundle (can be extracted to a public repo `renewio-security-scanners` for free GHA minutes). It never holds Apple signing credentials.

## Workflow

`workflow_dispatch` → download release IPA + source archive → verify SHA-256 → run adapters → normalize report → POST to Supabase `submit-report`.

## Inputs

| Input | Required | Description |
|-------|----------|-------------|
| `job_id` | yes | Supabase `scan_jobs.id` |
| `github_owner` | yes | Repo owner |
| `github_repo` | yes | Repo name |
| `release_tag` | yes | Release tag |
| `source_commit` | no | Exact commit SHA if known |
| `asset_id` | no | GitHub release asset id |
| `expected_sha256` | yes | Client-computed IPA hash |
| `policy_version` | yes | e.g. `v1` |
| `callback_url` | yes | Supabase submit-report URL |

## Secrets

- `SUBMIT_REPORT_HMAC_SECRET` — shared with Supabase Edge Function
- `GITHUB_TOKEN` — default Actions token (public repos)

## Local dry-run

```bash
./scripts/run-local.sh --source ./fixtures/insecure-sample --ipa /path/to/app.ipa --expected-sha256 <hex>
```

## Scanner bundle version

See `policy/v1.json` → `scanner_bundle_version`.
