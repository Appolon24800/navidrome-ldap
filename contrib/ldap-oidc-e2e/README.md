# LDAP and OIDC end-to-end check

`run.sh` exercises the features this fork adds, on a real `navidrome` binary:

- LDAP login against a private OpenLDAP directory, including the admin group mapping.
- App passwords: Subsonic API access, web login and revocation.
- The LDAP liveness sweep: revoking app passwords and recomputing admin status.
- OIDC web login through a fake provider: linking an existing account and creating a new one.

The directory, the provider and two `navidrome` instances listen on loopback only
(ports 3899, 4534, 4535 and 5556 by default). They live in a temporary directory and
stop when the script ends.

## Prerequisites

- `go` and `python3`
- OpenLDAP server and client tools: `slapd`, `ldapadd`, `ldapmodify`, `ldapdelete`.
  On Debian and Ubuntu: `apt install slapd ldap-utils`. There the AppArmor profile of the
  `slapd` package blocks a private instance in a temporary directory. Unload it first:
  `sudo apparmor_parser -R /etc/apparmor.d/usr.sbin.slapd`.

## Run

```sh
make build
contrib/ldap-oidc-e2e/run.sh ./navidrome
```

The script prints one `PASS` or `FAIL` line per check and exits non-zero when a check
fails. It takes about a minute, half of it waiting for two liveness sweeps.

`.github/workflows/sync.yml` runs it on every merge before pushing.
