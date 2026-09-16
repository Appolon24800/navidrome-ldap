# Upstream Sync Workflow — Design

Date: 2026-09-16
Status: approved

## Problem

`sync.yml` merges `upstream/main` from `joestump/navidrome-ldap` — a ref that
does not exist (that repo's default branch is `master`). The job has failed
every scheduled run, emailing the owner daily. Additionally, pushes made with
`GITHUB_TOKEN` never trigger `docker.yml` (`on: push`), so even a successful
auto-merge would have produced no image.

## Decisions

- **Track `navidrome/navidrome` master only.** Joe Stump's LDAP fork stays a
  manual cherry-pick source; it is not auto-merged.
- **Fully silent on unmergeable days.** A conflicting merge aborts and the run
  exits 0. No issue, no email. Push failures (real infra errors) still fail.
- **Docker builds only when something merged.** `docker.yml` gains
  `workflow_call` and is invoked directly by the sync workflow after a push,
  which bypasses the `GITHUB_TOKEN` recursion guard.

## Design

`sync.yml` (daily 06:00 UTC + manual dispatch, `permissions: contents: write`):

1. Full checkout, fetch `navidrome/navidrome` master.
2. `git merge-base --is-ancestor navidrome/master HEAD` → true: log "up to
   date", output `pushed=false`, end. No build.
3. `git merge navidrome/master --no-edit`:
   - success → `git push`, output `pushed=true`.
   - conflict → `git merge --abort`, log "manual merge needed", output
     `pushed=false`. Run is green.
4. Job `build` (`if: pushed == 'true'`) calls `.github/workflows/docker.yml`
   as a reusable workflow with `secrets: inherit` and
   `permissions: {contents: read, packages: write}`.

`docker.yml`: adds `workflow_call:` to its `on:` block. Unchanged otherwise;
direct pushes to master still build via `on: push`.

## Rollout

Commit the workflow changes, merge the 53 pending upstream commits (manual
conflict resolution if needed), push once — starting the workflow from a
fresh, green baseline.
