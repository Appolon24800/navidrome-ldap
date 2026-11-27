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

## Revision 2026-11-27

"Fully silent on unmergeable days" hid the problem it was meant to avoid.
Upstream commits `fed35e08` and `b76ae142` (2026-09-19) added Jellyfin options
next to the fork's LDAP options in `conf/configuration.go` and a route next to
`api.addAppPasswordRoute` in `server/nativeapi/native_api.go`. Every run from
2026-09-20 conflicted, exited 0, and went unnoticed. The last automatic merge
was run 35332952302 on 2026-09-18. On 2026-11-27 the fork was 173 commits
behind upstream, with 22 conflicted paths.

Decisions:

- **A blocked sync is visible.** A conflicting merge, or a clean merge that
  fails the build, the tests or the end-to-end check, fails the run and writes
  the conflicted files, or the last 60 log lines, to the run summary. Failed
  scheduled runs email the owner, which is how the broken 2026-08 runs surfaced.
- **The tracking issue needs the Issues feature.** With Issues enabled, the
  same run opens or updates one issue titled "Upstream sync needs attention"
  with the details and the commands to resolve them. This fork has Issues
  disabled (2026-11-27), so there the failed run is the only signal.
- **A clean merge is tested before it is pushed.** `git merge --no-commit`
  leaves the merge uncommitted, `make build test test-js` and
  `contrib/ldap-oidc-e2e/run.sh` run on the merged tree, and only a passing
  tree is committed and pushed. The end-to-end check drives LDAP login, app
  passwords, the liveness sweep and the OIDC login on the built binary, against
  a private OpenLDAP directory and a fake OIDC provider.
- **Tests are part of the gate because a merge can be conflict-free and still
  break the fork.** Upstream changed the context key `parseUserIDMiddleware`
  stores the user id under. The fork's app password handlers read the old key,
  so every app password request failed with 403 or a panic. Only a test against
  the real router showed it.
- **The issue closes itself** on the next run that finds the branch up to
  date, which also covers a manual merge pushed to master.
- **A manual run can check a branch without merging.** `workflow_dispatch`
  with `verify_only` runs the build, the tests and the end-to-end check on the
  selected branch.
- **Fork options leave `configuration.go`.** The LDAP and OIDC option structs,
  validators and viper defaults now live in `conf/ldap.go` and `conf/oidc.go`.
  The fork's footprint in `conf/configuration.go` is seven lines, so upstream
  edits to that file merge on their own.
