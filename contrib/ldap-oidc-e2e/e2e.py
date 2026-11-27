#!/usr/bin/env python3
"""Checks run by run.sh against two navidrome instances: one backed by a private
OpenLDAP directory, one with OIDC login through a fake provider. Covers LDAP login,
admin mapping, app passwords, the liveness sweep and the OIDC web login."""
import base64
import hashlib
import http.client
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
import urllib.parse

# Ports and the working directory are set by run.sh.
HOST = "127.0.0.1"
LDAP_PORT = int(os.environ["E2E_LDAP_PORT"])
OIDC_PORT = int(os.environ["E2E_OIDC_PORT"])
IDP_PORT = int(os.environ["E2E_IDP_PORT"])
SLAPD_PORT = os.environ["E2E_SLAPD_PORT"]
CALLBACK = f"http://{HOST}:{OIDC_PORT}/music/auth/oidc/callback"
E = os.environ["E2E_WORK"]
results = []


def req(port, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection(HOST, port, timeout=30)
    h = dict(headers or {})
    data = None
    if body is not None:
        data = body if isinstance(body, str) else json.dumps(body)
        h.setdefault("Content-Type", "application/json")
    conn.request(method, path, body=data.encode() if data is not None else None, headers=h)
    resp = conn.getresponse()
    raw, headers_out = resp.read(), resp.getheaders()
    conn.close()
    return resp.status, headers_out, raw


def header(headers, name):
    return next((v for k, v in headers if k.lower() == name), "")


def cookie_of(headers):
    return header(headers, "set-cookie").split(";")[0]


def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    print(("PASS  " if cond else "FAIL  ") + name + (f"  [{detail}]" if detail else ""), flush=True)


def claims(token):
    pad = lambda s: s + "=" * (-len(s) % 4)
    return json.loads(base64.urlsafe_b64decode(pad(token.split(".")[1])))


def create_admin(port, username, password):
    return req(port, "POST", "/music/auth/createAdmin", {"username": username, "password": password})


def login(port, username, password):
    return req(port, "POST", "/music/auth/login", {"username": username, "password": password})


def api(port, path, token, method="GET", body=None):
    headers = {"X-ND-Authorization": "BEARER " + token}  # the header the Navidrome UI uses
    if body is not None:
        headers["Content-Type"] = "application/json"
    return req(port, method, "/music" + path, body, headers)


def rest(port, **params):
    query = urllib.parse.urlencode({"v": "1.16.1", "c": "e2e", "f": "json", **params})
    status, _, raw = req(port, "GET", "/music/rest/ping?" + query)
    body = json.loads(raw)["subsonic-response"]
    return status, body.get("status"), body


def users_of(port, token):
    return {u["userName"]: u for u in json.loads(api(port, "/api/user", token)[2])}


def app_passwords_of(port, token, user_id):
    return json.loads(api(port, f"/api/user/{user_id}/app-password", token)[2])


def create_app_password(port, token, user_id, name):
    status, _, raw = api(port, f"/api/user/{user_id}/app-password", token, "POST", {"name": name})
    return status, (json.loads(raw).get("secret") if status == 201 else None), (json.loads(raw).get("id") if status == 201 else "")


LDAP_ARGS = ["-H", f"ldap://{HOST}:{SLAPD_PORT}", "-x", "-D", "cn=Service,dc=example,dc=org", "-w", "service-secret"]


def ldap_delete(dn):
    out = subprocess.run(["ldapdelete", *LDAP_ARGS, dn], capture_output=True, text=True)
    return out.returncode, (out.stdout + out.stderr).strip()


def ldap_modify(ldif):
    out = subprocess.run(["ldapmodify", *LDAP_ARGS], input=ldif, capture_output=True, text=True)
    return out.returncode, (out.stdout + out.stderr).strip()


# ---------------------------------------------------------------- LDAP instance
print("\n== LDAP login and admin mapping (instance backed by OpenLDAP) ==")
status, _, raw = create_admin(LDAP_PORT, "root", "rootpass")
first = json.loads(raw) if status == 200 else {}
check("first admin is created through /auth/createAdmin", status == 200 and first.get("isAdmin") is True, f"HTTP {status}")
root_token = first.get("token", "")
users = users_of(LDAP_PORT, root_token)
root_id = users["root"]["id"]

status, _, raw = login(LDAP_PORT, "alice", "wonderland")
alice = json.loads(raw) if status == 200 else {}
check("directory password logs alice in", status == 200 and alice.get("name") == "Alice Liddell", f"HTTP {status}")
check("memberOf the admin group makes alice admin", alice.get("isAdmin") is True, f"isAdmin={alice.get('isAdmin')}")

status, _, raw = login(LDAP_PORT, "bob", "builderpw")
bob = json.loads(raw) if status == 200 else {}
check("directory password logs bob in", status == 200, f"HTTP {status}")
check("bob is outside the admin group, so he is not admin", bob.get("isAdmin") is False, f"isAdmin={bob.get('isAdmin')}")

status, _, _ = login(LDAP_PORT, "alice", "wrong")
check("a wrong directory password is rejected", status == 401, f"HTTP {status}")
status, _, _ = login(LDAP_PORT, "ghost", "whatever")
check("a user missing from the directory is rejected", status == 401, f"HTTP {status}")
status, _, _ = login(LDAP_PORT, "alice", "")
check("an empty password is rejected", status == 401, f"HTTP {status}")
status, _, _ = login(LDAP_PORT, "root", "rootpass")
check("a local password still works with LDAP configured", status == 200, f"HTTP {status}")

users = users_of(LDAP_PORT, root_token)
check("directory users are stored with authType=ldap",
      users["alice"]["authType"] == "ldap" and users["bob"]["authType"] == "ldap",
      f"alice={users['alice']['authType']} bob={users['bob']['authType']}")
check("the local admin keeps authType=local", users["root"]["authType"] == "local")
alice_id, bob_id = users["alice"]["id"], users["bob"]["id"]

db = sqlite3.connect(f"file:{E}/nd-ldap/data/navidrome.db?mode=ro", uri=True)
rows = {r[0]: r[1:] for r in db.execute("select user_name, auth_type, password, is_admin from user")}
db.close()
check("directory passwords are not stored", rows["alice"][1] == "" and rows["bob"][1] == "",
      f"alice={rows['alice'][1]!r} bob={rows['bob'][1]!r}")
check("the local password is stored encrypted", rows["root"][1] not in ("", "rootpass"), "")

print("\n== App passwords (Subsonic API and web login) ==")
status, state, body = rest(LDAP_PORT, u="bob", p="builderpw")
check("Subsonic rejects the directory password of an LDAP user", state == "failed" and body["error"]["code"] == 40, f"{state}")
status, secret, ap_id = create_app_password(LDAP_PORT, root_token, bob_id, "Tempus")
check("an admin creates an app password for bob", status == 201 and len(secret or "") > 20, f"HTTP {status}")
status, state, body = rest(LDAP_PORT, u="bob", p=secret)
check("Subsonic accepts the app password as p=", state == "ok", f"{state}")
status, state, body = rest(LDAP_PORT, u="bob", t=hashlib.md5((secret + "e2esalt").encode()).hexdigest(), s="e2esalt")
check("Subsonic accepts the app password as salt+token", state == "ok", f"{state}")
status, state, body = rest(LDAP_PORT, u="bob", p="enc:" + secret.encode().hex())
check("Subsonic accepts a hex-encoded app password (enc:)", state == "ok", f"{state}")
status, state, body = rest(LDAP_PORT, u="root", p="rootpass")
check("Subsonic still accepts a local user's password", state == "ok", f"{state}")
status, state, body = rest(LDAP_PORT, u="root", p="wrong")
check("Subsonic rejects a wrong local password", state == "failed", f"{state}")

status, _, raw = login(LDAP_PORT, "bob", secret)
bob_web = json.loads(raw) if status == 200 else {}
check("web login with an app password succeeds for an LDAP user", status == 200, f"HTTP {status}")
web_claims = claims(bob_web["token"]) if bob_web.get("token") else {}
check("that session token carries the app password id and name",
      bool(web_claims.get("apid")) and web_claims.get("apnm") == "Tempus", f"claims={sorted(web_claims)}")
expected = hashlib.md5((secret + bob_web["subsonicSalt"]).encode()).hexdigest()
check("subsonicToken of that login is derived from the app password", bob_web.get("subsonicToken") == expected)
status, _, _ = api(LDAP_PORT, f"/api/user/{bob_id}/app-password", bob_web.get("token", "x"))
check("the native API accepts that session", status == 200, f"HTTP {status}")
status, _, _ = api(LDAP_PORT, f"/api/user/{alice_id}/app-password", bob_web.get("token", "x"))
check("a non-admin cannot list another user's app passwords", status == 403, f"HTTP {status}")

status, root_secret, _ = create_app_password(LDAP_PORT, root_token, root_id, "Root player")
status, state, body = rest(LDAP_PORT, u="root", p=root_secret)
check("Subsonic accepts an app password of a local user", state == "ok", f"{state}")
status, _, _ = login(LDAP_PORT, "root", root_secret)
check("web login with an app password is refused for a local user", status == 401, f"HTTP {status}")

status, _, _ = api(LDAP_PORT, f"/api/user/{alice_id}/app-password/{ap_id}", root_token, "DELETE")
check("revoking through a mismatched user path returns 404", status == 404, f"HTTP {status}")
status, _, _ = api(LDAP_PORT, f"/api/user/{bob_id}/app-password/{ap_id}", root_token, "DELETE")
check("the admin revokes bob's app password", status == 200, f"HTTP {status}")
status, state, body = rest(LDAP_PORT, u="bob", p=secret)
check("Subsonic rejects the revoked app password", state == "failed", f"{state}")
status, _, _ = api(LDAP_PORT, f"/api/user/{bob_id}/app-password", bob_web.get("token", "x"))
check("the web session backed by the revoked app password is rejected", status == 401, f"HTTP {status}")
status, _, _ = login(LDAP_PORT, "bob", secret)
check("web login with the revoked app password fails", status == 401, f"HTTP {status}")

status, _, _ = req(LDAP_PORT, "GET", "/music/auth/oidc/login")
check("OIDC routes are not mounted when OIDC is disabled", status == 404, f"HTTP {status}")

print("\n== LDAP liveness sweep and admin recompute (@every 20s) ==")
status, _, raw = login(LDAP_PORT, "carol", "carolpw")
carol = json.loads(raw) if status == 200 else {}
check("an entry matching DisabledFilter can log in until the next sweep", status == 200, f"HTTP {status}")
carol_id = carol.get("id", "")
secrets = {}
for name, user_id in (("alice", alice_id), ("bob", bob_id), ("carol", carol_id)):
    _, secrets[name], _ = create_app_password(LDAP_PORT, root_token, user_id, f"Liveness {name}")
check("three app passwords created for the sweep", all(secrets.values()), str({k: bool(v) for k, v in secrets.items()}))

code, out = ldap_delete("uid=bob,ou=people,dc=example,dc=org")
check("bob is removed from the directory", code == 0, out)
code, out = ldap_modify("dn: cn=navidrome-admins,ou=groups,dc=example,dc=org\nchangetype: modify\nadd: member\n"
                        "member: uid=carol,ou=people,dc=example,dc=org\n")
check("carol is added to the admin group", code == 0, out)

time.sleep(25)
users = users_of(LDAP_PORT, root_token)
aps = {name: app_passwords_of(LDAP_PORT, root_token, uid) for name, uid in (("alice", alice_id), ("bob", bob_id), ("carol", carol_id))}
check("the sweep revokes the app passwords of a user missing from the directory",
      bool(aps["bob"]) and all(a.get("revokedAt") for a in aps["bob"]), str([(a["name"], a.get("revokedAt")) for a in aps["bob"]]))
check("the sweep revokes the app passwords of a user matching DisabledFilter",
      bool(aps["carol"]) and all(a.get("revokedAt") for a in aps["carol"]), str([(a["name"], a.get("revokedAt")) for a in aps["carol"]]))
check("the sweep keeps the app passwords of an active user", bool(aps["alice"]) and not any(a.get("revokedAt") for a in aps["alice"]))
check("the sweep promotes a user added to the admin group", users["carol"]["isAdmin"] is True, f"isAdmin={users['carol']['isAdmin']}")
check("the sweep keeps alice admin", users["alice"]["isAdmin"] is True)
status, state, body = rest(LDAP_PORT, u="carol", p=secrets["carol"])
check("Subsonic rejects an app password revoked by the sweep", state == "failed", f"{state}")

code, out = ldap_modify("dn: cn=navidrome-admins,ou=groups,dc=example,dc=org\nchangetype: modify\ndelete: member\n"
                        "member: uid=alice,ou=people,dc=example,dc=org\n")
check("alice is removed from the admin group", code == 0, out)
time.sleep(25)
users = users_of(LDAP_PORT, root_token)
check("the sweep demotes a user removed from the admin group", users["alice"]["isAdmin"] is False, f"isAdmin={users['alice']['isAdmin']}")
check("the sweep leaves the local admin alone", users["root"]["isAdmin"] is True)

# ---------------------------------------------------------------- OIDC instance
print("\n== OIDC web login (instance with the fake provider) ==")
status, _, raw = create_admin(OIDC_PORT, "alice", "adminpass")
local = json.loads(raw) if status == 200 else {}
check("first admin of the OIDC instance is created", status == 200 and local.get("isAdmin") is True, f"HTTP {status}")
local_admin = users_of(OIDC_PORT, local.get("token", "x"))["alice"]

status, _, raw = req(OIDC_PORT, "GET", "/music/app/")
match = re.search(r'window\.__APP_CONFIG__ = "(.*)"', raw.decode())
ui_config = json.loads(json.loads('"' + match.group(1) + '"')) if match else {}
check("the served UI config turns OIDC on", ui_config.get("oidcEnabled") is True and ui_config.get("oidcAutoRedirect") is False,
      f"oidcEnabled={ui_config.get('oidcEnabled')}")
check("the served UI config names the provider", ui_config.get("oidcDisplayName") == "PocketID", "")

status, headers, raw = req(OIDC_PORT, "GET", "/music/auth/oidc/login")
start_url = urllib.parse.urlparse(header(headers, "location"))
start_query = urllib.parse.parse_qs(start_url.query)
tx_cookie = cookie_of(headers)
check("start redirects to the provider's authorize endpoint",
      status == 302 and f"http://{start_url.netloc}{start_url.path}" == f"http://{HOST}:{IDP_PORT}/authorize", f"HTTP {status}")
check("the authorization request carries PKCE S256, nonce, state and the callback URL",
      start_query.get("code_challenge_method") == ["S256"] and bool(start_query.get("code_challenge"))
      and bool(start_query.get("nonce")) and bool(start_query.get("state")) and start_query.get("redirect_uri") == [CALLBACK],
      f"params={sorted(start_query)}")
check("start sets the HttpOnly transaction cookie",
      tx_cookie.startswith("navidrome_oidc=") and "httponly" in header(headers, "set-cookie").lower(), tx_cookie[:22] + "...")


def oidc_login(user):
    """Runs start, authorization and callback. Returns the callback status, its Location and the handoff cookie."""
    _, headers, _ = req(OIDC_PORT, "GET", "/music/auth/oidc/login")
    location, cookie = header(headers, "location"), cookie_of(headers)
    authorize_path = location.split(f"{HOST}:{IDP_PORT}", 1)[1] + "&user=" + user
    status, headers, _ = req(IDP_PORT, "GET", authorize_path)
    back = header(headers, "location")
    if status != 302 or not back.startswith(CALLBACK + "?"):
        return status, back, ""
    status, headers, _ = req(OIDC_PORT, "GET", back.split(f"{HOST}:{OIDC_PORT}", 1)[1], headers={"Cookie": cookie})
    return status, header(headers, "location"), cookie_of(headers)


status, back, handoff = oidc_login("alice")
check("the callback lands on the UI with ?oidc=complete", status == 303 and back.endswith("/music/app/#/login?oidc=complete"), f"HTTP {status} {back}")
check("the callback sets a new one-use handoff cookie", handoff.startswith("navidrome_oidc=") and handoff != tx_cookie, handoff[:22] + "...")
origin = f"http://{HOST}:{OIDC_PORT}"
session_headers = {"Cookie": handoff, "Origin": origin, "Content-Type": "application/json"}
status, _, _ = req(OIDC_PORT, "POST", "/music/auth/oidc/session", "{}", {**session_headers, "Origin": "https://evil.example"})
check("a handoff presented from another origin is refused", status == 403, f"HTTP {status}")
status, _, raw = req(OIDC_PORT, "POST", "/music/auth/oidc/session", "{}", session_headers)
session = json.loads(raw) if status == 200 else {}
check("the handoff is exchanged for a session", status == 200 and bool(session.get("token")), f"HTTP {status}")
check("the session belongs to the existing account named by the provider",
      session.get("username") == "alice" and session.get("id") == local_admin["id"] and session.get("isAdmin") is True,
      f"user={session.get('username')} admin={session.get('isAdmin')}")
sclaims = claims(session.get("token", "a.eyJhIjoxfQ.c"))
check("the session token has an absolute deadline",
      isinstance(sclaims.get("maxexp"), int) and sclaims.get("sub") == "alice", f"claims={sorted(sclaims)}")
check("the session response carries no provider token", "fake-access-token" not in raw.decode(), "")
status, _, _ = api(OIDC_PORT, f"/api/user/{session.get('id')}", session.get("token", "x"))
check("the native API accepts the OIDC session", status == 200, f"HTTP {status}")
status, _, _ = req(OIDC_PORT, "POST", "/music/auth/oidc/session", "{}", session_headers)
check("a replayed handoff is refused", status == 401, f"HTTP {status}")

status, back, handoff = oidc_login("new-listener")
status, _, raw = req(OIDC_PORT, "POST", "/music/auth/oidc/session", "{}",
                     {"Cookie": handoff, "Origin": origin, "Content-Type": "application/json"})
provisioned = json.loads(raw) if status == 200 else {}
check("an unknown provider user gets a regular account",
      status == 200 and provisioned.get("isAdmin") is False and provisioned.get("username") == "new-listener",
      f"HTTP {status} user={provisioned.get('username')}")
users = users_of(OIDC_PORT, local.get("token", "x"))
check("the provisioned account is a local account and the admin stays admin",
      users["new-listener"]["authType"] == "local" and users["alice"]["isAdmin"] is True, "")
db = sqlite3.connect(f"file:{E}/nd-oidc/data/navidrome.db?mode=ro", uri=True)
generated = db.execute("select password from user where user_name='new-listener'").fetchone()[0]
db.close()
check("the provisioned account has a generated credential", bool(generated), "")

status, headers, _ = req(OIDC_PORT, "GET", "/music/auth/oidc/callback?code=x&state=y")
check("a callback without the transaction cookie fails closed",
      status == 303 and header(headers, "location").endswith("?oidc=failed"), f"HTTP {status} {header(headers, 'location')}")

status, _, _ = login(OIDC_PORT, "alice", "adminpass")
check("password login still works next to OIDC", status == 200, f"HTTP {status}")

print("\n== Server logs ==")
for name in ("nd-ldap", "nd-oidc"):
    log = open(f"{E}/{name}/navidrome.log").read()
    errors = [line for line in log.splitlines() if "level=error" in line or "panic:" in line]
    check(f"{name}: no error or panic in the log since startup", not errors, "\n    ".join(errors[:5]))

print("\n== Summary ==")
failed = [r for r in results if not r[1]]
print(f"{len(results) - len(failed)} passed, {len(failed)} failed")
for name, _, detail in failed:
    print("  FAILED:", name, detail)
sys.exit(1 if failed else 0)
