"""Create the Resonator LLC ops account on the live instance (one-off) and print an agent token."""
import re, html, httpx, time, hmac, hashlib, struct, secrets, sys, pathlib
BASE = "https://secure.resonator.am"; AUTH = "https://auth.secure.resonator.am"


def totp(k):
    h = hmac.new(k.encode(), struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest(); o = h[-1] & 15
    return str((struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) % 10 ** 6).zfill(6)


def absu(u):
    u = html.unescape(u); return u if u.startswith("http") else AUTH + u


def fa(t):
    return absu(re.findall(r'<form[^>]+action="([^"]+)"', t)[0])


c = httpx.Client(follow_redirects=True, timeout=30)
r = c.get(BASE + "/login")
r = c.get(absu(re.search(r'href="([^"]*registration[^"]*)"', r.text).group(1)))
pw = "Ops-" + secrets.token_urlsafe(14)
r = c.post(fa(r.text), data={"email": "ops@resonator.am", "firstName": "Ops", "lastName": "Resonator", "password": pw, "password-confirm": pw})
sec = re.search(r'name="totpSecret" value="([^"]+)"', r.text).group(1)
r = c.post(fa(r.text), data={"totp": totp(sec), "totpSecret": sec, "userLabel": "ops"})
assert "Dashboard" in r.text
r = c.post(BASE + "/settings/tokens", data={"label": sys.argv[1] if len(sys.argv) > 1 else "secure-droplet"})
tok = re.search(r"(srt_[A-Za-z0-9_\-]+)", r.text).group(1)
p = pathlib.Path.home() / "secure-resonator/.ops-account"
p.write_text(f"email: ops@resonator.am\npassword: {pw}\ntotp_raw_secret: {sec}\nagent_token: {tok}\n"); p.chmod(0o600)
print(tok)
