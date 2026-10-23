"""End-to-end smoke test against the live deployment: register (password + mandatory TOTP), log in,
create an agent token, post an inventory with a known-vulnerable package, wait for findings + proposals, approve one, pull it as an agent."""
import re, sys, time, html, json, base64, hmac, hashlib, struct, secrets, httpx

BASE = "https://secure.resonator.am"
email = f"smoke-{secrets.token_hex(3)}@resonator.am"
pw = "Smoke-" + secrets.token_urlsafe(14)
c = httpx.Client(follow_redirects=True, timeout=30)


def totp(raw_secret):
    key = raw_secret.encode()  # Keycloak's hidden totpSecret is the raw key; the QR carries its base32 form
    msg = struct.pack(">Q", int(time.time()) // 30)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[-1] & 15
    return str((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 10 ** 6).zfill(6)


AUTH = "https://auth.secure.resonator.am"


def absu(u):
    u = html.unescape(u)
    return u if u.startswith("http") else AUTH + u


def form_action(page, idx=0):
    acts = re.findall(r'<form[^>]+action="([^"]+)"', page)
    return absu(acts[idx])


r = c.get(BASE + "/login")
assert "auth.secure.resonator.am" in str(r.url), r.url
reg = re.search(r'href="([^"]*registration[^"]*)"', r.text).group(1)
r = c.get(absu(reg))
r = c.post(form_action(r.text), data={"email": email, "firstName": "Smoke", "lastName": "Test", "password": pw, "password-confirm": pw})
assert "totpSecret" in r.text or "Mobile Authenticator" in r.text, ("no TOTP step", r.url, r.text[:500])
secret = re.search(r'name="totpSecret" value="([^"]+)"', r.text).group(1)
code = totp(secret)
r = c.post(form_action(r.text), data={"totp": code, "totpSecret": secret, "userLabel": "smoke", "logout-sessions": "on"})
assert str(r.url).startswith(BASE), ("not back at app", r.url, r.text[:300])
assert "Dashboard" in r.text and email in r.text, r.text[:400]
print("registered + TOTP + logged in as", email)

# log out and log in again, proving OTP is REQUIRED
c.get(BASE + "/logout")
r = c.get(BASE + "/login")
assert 'name="username"' in r.text, ("logout did not end the SSO session", r.url)
r = c.post(form_action(r.text), data={"username": email, "password": pw, "credentialId": ""})
assert 'name="otp"' in r.text, "OTP not required on login!"
time.sleep(31 - int(time.time()) % 30)  # Keycloak refuses a code reused inside the same window
r = c.post(form_action(r.text), data={"otp": totp(secret)})
assert "Dashboard" in r.text, r.text[:300]
print("re-login requires OTP: ok")

r = c.post(BASE + "/settings/tokens", data={"label": "smoke"})
tok = re.search(r"(srt_[A-Za-z0-9_\-]+)", r.text).group(1)
api = httpx.Client(headers={"Authorization": f"Bearer {tok}"}, timeout=30)
inv = {"host": "smoke-host", "os": "Debian GNU/Linux 12 (bookworm)", "components": [
    {"ecosystem": "Debian", "name": "openssl", "version": "3.0.11-1~deb12u1"},
    {"ecosystem": "npm", "name": "lodash", "version": "4.17.15"},
    {"ecosystem": "PyPI", "name": "requests", "version": "2.25.0"},
    {"ecosystem": "PyPI", "name": "httpx", "version": "0.27.0"}]}
print("inventory:", api.post(BASE + "/api/v1/inventory", json=inv).json())
assert httpx.post(BASE + "/api/v1/inventory", json=inv).status_code == 401

for i in range(30):
    r = c.get(BASE + "/")
    m = re.search(r'<b style="color:var\(--bad\)">(\d+)</b>', r.text)
    pend = re.search(r'<b style="color:var\(--warn\)">(\d+)</b>', r.text)
    if m and int(m.group(1)) > 0 and int(pend.group(1)) > 0:
        break
    time.sleep(5)
print("open findings:", m.group(1), "pending proposals:", pend.group(1))
assert int(m.group(1)) > 0
pid = re.search(r'/proposals/(\d+)', r.text).group(1)
r = c.get(f"{BASE}/proposals/{pid}")
print("proposal:", re.search(r"<h1>(.*?)</h1>", r.text).group(1))
assert api.get(BASE + "/api/v1/proposals?status=approved").json() == []
c.post(f"{BASE}/proposals/{pid}/decide", data={"decision": "approved"})
appr = api.get(BASE + "/api/v1/proposals?status=approved").json()
assert len(appr) == 1 and str(appr[0]["id"]) == pid
print("approved and visible to agent:", appr[0]["title"], "steps:", len(appr[0]["steps"]))
print(api.post(f"{BASE}/api/v1/proposals/{pid}/result", json={"ok": True, "log": "smoke: not really executed"}).json())
r = c.get(f"{BASE}/hosts/" + re.search(r'/hosts/(\d+)', c.get(BASE + "/").text).group(1))
print("host page ok:", "smoke-host" in r.text)
print("ALL OK")
