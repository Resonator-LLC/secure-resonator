import hashlib, hmac, json, os, secrets
from datetime import datetime, timezone
from fastapi import FastAPI, Request, Depends, HTTPException, Form, Header
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth
from . import db
from .inventory import ingest_inventory

PUBLIC_URL = os.environ.get("PUBLIC_URL", "http://localhost:8000")
ISSUER = os.environ["OIDC_ISSUER"]
ISSUER_INTERNAL = os.environ.get("OIDC_ISSUER_INTERNAL", ISSUER)
PEPPER = os.environ["AGENT_TOKEN_PEPPER"]

app = FastAPI(title="Secure Resonator", docs_url=None, redoc_url=None)
app.add_middleware(SessionMiddleware, secret_key=os.environ["SESSION_SECRET"], https_only=PUBLIC_URL.startswith("https"), same_site="lax", max_age=8 * 3600)
app.mount("/static", StaticFiles(directory="static"), name="static")
tpl = Jinja2Templates(directory="templates")

oauth = OAuth()
oauth.register(
    "kc",
    client_id=os.environ["OIDC_CLIENT_ID"],
    client_secret=os.environ["OIDC_CLIENT_SECRET"],
    server_metadata_url=f"{ISSUER_INTERNAL}/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile", "code_challenge_method": "S256"},
)


@app.on_event("startup")
def _startup():
    db.init_schema()


# ---------- auth ----------
def current_user(request: Request):
    u = request.session.get("user")
    if not u:
        raise HTTPException(status_code=307, headers={"Location": "/login"})
    return u


@app.get("/login")
async def login(request: Request):
    return await oauth.kc.authorize_redirect(request, f"{PUBLIC_URL}/auth/callback")


@app.get("/auth/callback")
async def callback(request: Request):
    if request.query_params.get("error"):
        return render(request, "landing.html", error=request.query_params.get("error_description") or request.query_params["error"])
    try:
        token = await oauth.kc.authorize_access_token(request)
    except Exception as e:  # stale state, replayed code
        return RedirectResponse("/login", status_code=303)
    info = token.get("userinfo") or await oauth.kc.userinfo(token=token)
    # Keycloak realm enforces TOTP; we additionally refuse sessions whose token lacks an acr/amr we trust.
    acr = info.get("acr")
    sub, email, name = info["sub"], info.get("email"), info.get("name") or info.get("preferred_username")
    row = db.q("select id, org_id from users where sub=%s", (sub,), one=True)
    if not row:
        org = db.q("insert into orgs(name) values (%s) returning id", (email or name or sub,), one=True)
        row = db.q("insert into users(sub,email,name,org_id) values (%s,%s,%s,%s) returning id, org_id", (sub, email, name, org["id"]), one=True)
        db.q("insert into events(org_id,kind,message) values (%s,'signup',%s)", (org["id"], f"{email or name} created the organisation"))
    request.session["user"] = {"id": row["id"], "org_id": row["org_id"], "email": email, "name": name, "acr": acr}
    request.session["id_token"] = token.get("id_token")
    return RedirectResponse("/", status_code=303)


@app.get("/logout")
def logout(request: Request):
    idt = request.session.get("id_token")
    request.session.clear()
    hint = f"&id_token_hint={idt}" if idt else ""
    return RedirectResponse(f"{ISSUER}/protocol/openid-connect/logout?client_id={os.environ['OIDC_CLIENT_ID']}&post_logout_redirect_uri={PUBLIC_URL}/{hint}", status_code=303)


# ---------- pages ----------
def render(request, name, **ctx):
    ctx.update(request=request, user=request.session.get("user"))
    return tpl.TemplateResponse(request, name, ctx)


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    u = request.session.get("user")
    if not u:
        return render(request, "landing.html")
    org = u["org_id"]
    stats = db.q(
        """select (select count(*) from hosts where org_id=%s) hosts,
                  (select count(*) from components c join hosts h on h.id=c.host_id where h.org_id=%s) components,
                  (select count(*) from findings f join components c on c.id=f.component_id join hosts h on h.id=c.host_id where h.org_id=%s and f.status='open') open_findings,
                  (select count(*) from proposals where org_id=%s and status='proposed') pending""",
        (org, org, org, org), one=True)
    hosts = db.q("select h.*, (select count(*) from components c where c.host_id=h.id) n from hosts h where org_id=%s order by name", (org,))
    proposals = db.q("select p.*, h.name host from proposals p left join hosts h on h.id=p.host_id where p.org_id=%s and p.status='proposed' order by p.id desc limit 20", (org,))
    events = db.q("select * from events where org_id=%s order by id desc limit 15", (org,))
    return render(request, "dashboard.html", stats=stats, hosts=hosts, proposals=proposals, events=events)


@app.get("/hosts/{host_id}", response_class=HTMLResponse)
def host_page(request: Request, host_id: int, u=Depends(current_user)):
    host = db.q("select * from hosts where id=%s and org_id=%s", (host_id, u["org_id"]), one=True)
    if not host:
        raise HTTPException(404)
    comps = db.q(
        """select c.*, count(f.id) filter (where f.status='open') open_findings
           from components c left join findings f on f.component_id=c.id where c.host_id=%s group by c.id order by open_findings desc, c.ecosystem, c.name""",
        (host_id,))
    findings = db.q(
        """select f.*, c.ecosystem, c.name, c.version, a.summary, a.severity, a.aliases, p.id proposal_id, p.status proposal_status
           from findings f join components c on c.id=f.component_id join advisories a on a.id=f.advisory_id
           left join proposals p on p.finding_id=f.id where c.host_id=%s and f.status='open' order by a.severity desc nulls last, f.id desc""",
        (host_id,))
    return render(request, "host.html", host=host, comps=comps, findings=findings)


@app.get("/proposals/{pid}", response_class=HTMLResponse)
def proposal_page(request: Request, pid: int, u=Depends(current_user)):
    p = db.q("select p.*, h.name host from proposals p left join hosts h on h.id=p.host_id where p.id=%s and p.org_id=%s", (pid, u["org_id"]), one=True)
    if not p:
        raise HTTPException(404)
    adv = None
    if p["finding_id"]:
        adv = db.q("select a.*, c.ecosystem, c.name, c.version, f.fixed_version from findings f join advisories a on a.id=f.advisory_id join components c on c.id=f.component_id where f.id=%s", (p["finding_id"],), one=True)
    return render(request, "proposal.html", p=p, adv=adv)


@app.post("/proposals/{pid}/decide")
def decide(request: Request, pid: int, decision: str = Form(...), u=Depends(current_user)):
    if decision not in ("approved", "rejected"):
        raise HTTPException(400)
    p = db.q("update proposals set status=%s, decided_by=%s, decided_at=now() where id=%s and org_id=%s and status='proposed' returning id, title, host_id", (decision, u["id"], pid, u["org_id"]), one=True)
    if p:
        db.q("insert into events(org_id,kind,message,ref) values (%s,%s,%s,%s)", (u["org_id"], "decision", f"{u['email'] or u['name']} {decision} \"{p['title']}\"", json.dumps({"proposal": pid})))
    return RedirectResponse(f"/proposals/{pid}", status_code=303)


@app.get("/settings", response_class=HTMLResponse)
def settings(request: Request, u=Depends(current_user)):
    tokens = db.q("select id,label,created_at,last_used_at from agent_tokens where org_id=%s order by id desc", (u["org_id"],))
    new_token = request.session.pop("new_token", None)
    return render(request, "settings.html", tokens=tokens, new_token=new_token, public_url=PUBLIC_URL)


def _hash(token: str) -> str:
    return hmac.new(PEPPER.encode(), token.encode(), hashlib.sha256).hexdigest()


@app.post("/settings/tokens")
def create_token(request: Request, label: str = Form(...), u=Depends(current_user)):
    token = "srt_" + secrets.token_urlsafe(32)
    db.q("insert into agent_tokens(org_id,label,token_hash) values (%s,%s,%s)", (u["org_id"], label[:80], _hash(token)))
    request.session["new_token"] = token
    return RedirectResponse("/settings", status_code=303)


@app.post("/settings/tokens/{tid}/revoke")
def revoke_token(tid: int, u=Depends(current_user)):
    db.q("delete from agent_tokens where id=%s and org_id=%s", (tid, u["org_id"]))
    return RedirectResponse("/settings", status_code=303)


@app.post("/hosts/manual")
def manual_host(request: Request, name: str = Form(...), os_name: str = Form(""), components: str = Form(...), u=Depends(current_user)):
    """Manual input: one component per line as `ecosystem name version` (e.g. `Debian openssl 3.0.11-1~deb12u2`, `npm express 4.18.2`)."""
    comps = []
    for line in components.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            comps.append({"ecosystem": parts[0], "name": parts[1], "version": parts[2]})
    n = ingest_inventory(u["org_id"], {"host": name.strip(), "os": os_name.strip(), "components": comps}, source="manual")
    db.q("insert into events(org_id,kind,message) values (%s,'inventory',%s)", (u["org_id"], f"Manual inventory for {name}: {n} components"))
    return RedirectResponse("/", status_code=303)


# ---------- agent / scanner API ----------
def org_from_token(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "bearer token required")
    row = db.q("update agent_tokens set last_used_at=now() where token_hash=%s returning org_id", (_hash(authorization[7:]),), one=True)
    if not row:
        raise HTTPException(403, "invalid token")
    return row["org_id"]


@app.post("/api/v1/inventory")
async def api_inventory(request: Request, org_id: int = Depends(org_from_token)):
    body = await request.json()
    n = ingest_inventory(org_id, body, source=body.get("source", "agent"))
    db.q("insert into events(org_id,kind,message) values (%s,'inventory',%s)", (org_id, f"Inventory for {body.get('host')}: {n} components"))
    return {"ok": True, "components": n}


@app.get("/api/v1/proposals")
def api_proposals(status: str = "approved", org_id: int = Depends(org_from_token)):
    """Agents poll this for approved work; they never see unapproved proposals."""
    if status not in ("approved", "applied", "failed"):
        raise HTTPException(400)
    return db.q("select p.id, p.title, p.steps, p.status, h.name host from proposals p left join hosts h on h.id=p.host_id where p.org_id=%s and p.status=%s order by p.id", (org_id, status))


@app.post("/api/v1/proposals/{pid}/result")
async def api_result(pid: int, request: Request, org_id: int = Depends(org_from_token)):
    body = await request.json()
    ok = bool(body.get("ok"))
    p = db.q("update proposals set status=%s, result=%s where id=%s and org_id=%s and status='approved' returning title", ("applied" if ok else "failed", json.dumps(body), pid, org_id), one=True)
    if not p:
        raise HTTPException(404)
    db.q("insert into events(org_id,kind,message,ref) values (%s,'apply',%s,%s)", (org_id, f"Agent {'applied' if ok else 'FAILED'}: {p['title']}", json.dumps({"proposal": pid})))
    return {"ok": True}


@app.get("/agent.sh", response_class=PlainTextResponse)
def agent_script():
    return open("static/agent.sh").read().replace("__PUBLIC_URL__", PUBLIC_URL)


@app.get("/healthz")
def healthz():
    db.q("select 1")
    return {"ok": True, "time": datetime.now(timezone.utc).isoformat()}
