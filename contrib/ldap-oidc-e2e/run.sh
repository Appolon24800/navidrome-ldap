#!/bin/sh
# End-to-end check of this fork's LDAP, app-password and OIDC features.
#
# Starts a private OpenLDAP directory, a fake OpenID Connect provider and two
# navidrome instances on loopback, runs e2e.py against them, then stops them.
#
# Usage: contrib/ldap-oidc-e2e/run.sh [path to the navidrome binary]
# The binary defaults to ./navidrome, which "make build" produces.
# Needs go, python3, slapd and the ldap* command line tools.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
BINARY=${1:-$PWD/navidrome}
case $BINARY in /*) ;; *) BINARY=$PWD/$BINARY ;; esac
[ -x "$BINARY" ] || { echo "navidrome binary not found or not executable: $BINARY" >&2; exit 2; }
for tool in go python3 slapd ldapadd ldapmodify ldapdelete; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing tool: $tool" >&2; exit 2; }
done
SLAPD=$(command -v slapd)

find_dir() { # find_dir <fallback list> <file that must exist>
  for dir in $1; do [ -f "$dir/$2" ] && { echo "$dir"; return 0; }; done
  return 1
}
SCHEMA=$(find_dir "${SCHEMA_DIR:-/etc/openldap/schema /etc/ldap/schema}" core.schema) ||
  { echo "OpenLDAP schema directory not found (no core.schema)" >&2; exit 2; }
# Debian and Ubuntu ship the mdb backend and the memberof overlay as modules. Other builds, and
# possibly this one, have them built in. MODULES is empty when no module directory exists.
MODULES=$(find_dir "${MODULE_DIR:-/usr/lib/openldap /usr/lib/ldap /usr/libexec/openldap}" memberof.so) || MODULES=""

WORK=$(mktemp -d "${TMPDIR:-/tmp}/navidrome-e2e.XXXXXX")
SLAPD_PORT=${SLAPD_PORT:-3899}
IDP_PORT=${IDP_PORT:-5556}
NAVIDROME_LDAP_PORT=${NAVIDROME_LDAP_PORT:-4534}
NAVIDROME_OIDC_PORT=${NAVIDROME_OIDC_PORT:-4535}
export E2E_WORK="$WORK" E2E_SLAPD_PORT="$SLAPD_PORT" E2E_IDP_PORT="$IDP_PORT"
export E2E_LDAP_PORT="$NAVIDROME_LDAP_PORT" E2E_OIDC_PORT="$NAVIDROME_OIDC_PORT"
PIDS=""
cleanup() {
  trap - EXIT INT TERM
  for pid in $PIDS; do kill "$pid" 2>/dev/null || true; done
  for pid in $PIDS; do wait "$pid" 2>/dev/null || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

wait_for_port() { # wait_for_port <port> <name>
  i=0
  until python3 -c "import socket,sys; socket.create_connection(('127.0.0.1', int(sys.argv[1])), 1)" "$1" 2>/dev/null; do
    i=$((i + 1))
    if [ "$i" -ge 60 ]; then echo "$2 did not start" >&2; return 1; fi
    sleep 0.5
  done
}

# OpenLDAP directory
mkdir -p "$WORK/ldap/data" "$WORK/ldap/slapd.d"
python3 - "$HERE/ldap/slapd.conf.in" "$WORK/slapd.conf" "$SCHEMA" "$WORK" "$MODULES" <<'PY'
import os
import sys
template, output, schema, work, modules = sys.argv[1:6]
module_dir = next((d for d in modules.split() if os.path.isdir(d)), "")
loads = [f"moduleload {name}.so" for name in ("back_mdb", "memberof") if os.path.isfile(f"{module_dir}/{name}.so")]
module_lines = "\n".join([f"modulepath {module_dir}", *loads] if loads else [])
text = open(template).read().replace("@SCHEMA@", schema).replace("@WORK@", work)
text = text.replace("@include_modulepath@", module_lines)
open(output, "w").write(text)
PY
"$SLAPD" -h "ldap://127.0.0.1:$SLAPD_PORT/" -f "$WORK/slapd.conf" -F "$WORK/ldap/slapd.d" -d 256 \
  > "$WORK/ldap/slapd.log" 2>&1 &
PIDS="$PIDS $!"
wait_for_port "$SLAPD_PORT" slapd
ldapadd -H "ldap://127.0.0.1:$SLAPD_PORT" -x -D "cn=Service,dc=example,dc=org" -w service-secret \
  -f "$HERE/ldap/data.ldif" > "$WORK/ldap/load.log" 2>&1 || { cat "$WORK/ldap/load.log" >&2; exit 1; }

# Fake OpenID Connect provider
(cd "$HERE/fakeidp" && go build -o "$WORK/fakeidp" .)
FAKEIDP_LISTEN="127.0.0.1:$IDP_PORT" \
  FAKEIDP_REDIRECT="http://127.0.0.1:$NAVIDROME_OIDC_PORT/music/auth/oidc/callback" \
  "$WORK/fakeidp" > "$WORK/fakeidp.log" 2>&1 &
PIDS="$PIDS $!"
wait_for_port "$IDP_PORT" "the fake OIDC provider"

# Two navidrome instances, one with LDAP and one with OIDC, listening on loopback only.
# ND_AUTHREQUESTLIMIT is raised because every request comes from one address.
start_navidrome() { # start_navidrome <name> <port> [ND_... assignments]
  name=$1
  port=$2
  shift 2
  mkdir -p "$WORK/$name/data" "$WORK/$name/cache" "$WORK/$name/music"
  (
    cd "$WORK/$name"
    exec env -i PATH="$PATH" HOME="$HOME" \
      ND_ADDRESS=127.0.0.1 ND_PORT="$port" ND_BASEURL=/music ND_LOGLEVEL=info \
      ND_DATAFOLDER="$WORK/$name/data" ND_CACHEFOLDER="$WORK/$name/cache" ND_MUSICFOLDER="$WORK/$name/music" \
      ND_LOGFILE="$WORK/$name/navidrome.log" ND_SESSIONTIMEOUT=24h ND_AUTHREQUESTLIMIT=1000 \
      ND_ENABLEINSIGHTSCOLLECTOR=false ND_ENABLEEXTERNALSERVICES=false \
      ND_SCANNER_ENABLED=false ND_SCANNER_SCANONSTARTUP=false ND_PLUGINS_ENABLED=false \
      "$@" "$BINARY"
  ) > "$WORK/$name/stdout.log" 2>&1 &
  PIDS="$PIDS $!"
}
# LivenessSchedule, AdminGroup and DisabledFilter cannot be set through the environment, so they come from a file.
cat > "$WORK/nd-ldap.toml" <<EOF
[LDAP]
LivenessSchedule = "@every 20s"
AdminGroup = "cn=navidrome-admins,ou=groups,dc=example,dc=org"
DisabledFilter = "(description=disabled)"
EOF
start_navidrome nd-ldap "$NAVIDROME_LDAP_PORT" \
  ND_CONFIGFILE="$WORK/nd-ldap.toml" \
  ND_LDAP_HOST="ldap://127.0.0.1:$SLAPD_PORT" \
  ND_LDAP_BINDDN="cn=Service,dc=example,dc=org" ND_LDAP_BINDPASSWORD=service-secret ND_LDAP_BASE=dc=example,dc=org
start_navidrome nd-oidc "$NAVIDROME_OIDC_PORT" \
  ND_OIDC_ENABLED=true ND_OIDC_ISSUERURL="http://127.0.0.1:$IDP_PORT" ND_OIDC_CLIENTID=navidrome \
  ND_OIDC_CLIENTSECRET=navidrome-client-secret \
  ND_OIDC_REDIRECTURL="http://127.0.0.1:$NAVIDROME_OIDC_PORT/music/auth/oidc/callback" ND_OIDC_MAXSESSIONDURATION=1h
wait_for_port "$NAVIDROME_LDAP_PORT" "navidrome with LDAP"
wait_for_port "$NAVIDROME_OIDC_PORT" "navidrome with OIDC"

set +e
python3 "$HERE/e2e.py"
status=$?
set -e
if [ "$status" -ne 0 ]; then
  for log in "$WORK"/nd-*/navidrome.log "$WORK/ldap/slapd.log" "$WORK/fakeidp.log"; do
    echo "--- last lines of ${log#"$WORK"/} ---" >&2
    tail -n 15 "$log" >&2
  done
fi
exit "$status"
