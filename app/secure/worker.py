"""Advisory stream worker.
Loop: 1) match unscanned / stale components against OSV.dev (batch API), 2) store advisories + findings,
3) generate proposals (rule engine; LLM proposer plugs in here), 4) sleep.
OSV is the consolidated upstream for distro + language ecosystems; NVD/vendor feeds are added as further sources."""
import json, os, time, logging, httpx
from . import db
from .proposer import propose_for_finding

log = logging.getLogger("worker")
OSV = "https://api.osv.dev/v1"
RESCAN_HOURS = int(os.environ.get("RESCAN_HOURS", "6"))
BATCH = 500


def _queries(comps):
    out = []
    for c in comps:
        if c["purl"]:
            out.append({"package": {"purl": c["purl"]}})
        else:
            out.append({"version": c["version"], "package": {"name": c["name"], "ecosystem": c["ecosystem"]}})
    return out


def fixed_version(vuln, eco, name):
    for aff in vuln.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("name") != name:
            continue
        for r in aff.get("ranges", []):
            for ev in r.get("events", []):
                if "fixed" in ev:
                    return ev["fixed"]
    return None


def severity(vuln):
    sev = vuln.get("database_specific", {}).get("severity")
    if sev:
        return sev.upper()
    for s in vuln.get("severity", []):
        if s.get("type", "").startswith("CVSS"):
            return "CVSS:" + s.get("score", "")[:60]
    return None


def scan_once(client):
    comps = db.q(
        """select c.* from components c left join scan_state s on s.component_id=c.id
           where s.component_id is null or s.scanned_at < now() - make_interval(hours => %s) order by c.id limit %s""",
        (RESCAN_HOURS, BATCH))
    if not comps:
        return 0
    r = client.post(f"{OSV}/querybatch", json={"queries": _queries(comps)}, timeout=60)
    r.raise_for_status()
    results = r.json().get("results", [])
    n_new = 0
    for comp, res in zip(comps, results):
        vulns = res.get("vulns", [])
        ids = []
        for v in vulns:
            vid = v["id"]
            ids.append(vid)
            if not db.q("select 1 from advisories where id=%s and modified >= %s", (vid, v.get("modified")), one=True):
                full = client.get(f"{OSV}/vulns/{vid}", timeout=30).json()
                db.q(
                    """insert into advisories(id,summary,details,severity,aliases,published,modified,raw) values (%s,%s,%s,%s,%s,%s,%s,%s)
                       on conflict(id) do update set summary=excluded.summary, details=excluded.details, severity=excluded.severity,
                       aliases=excluded.aliases, modified=excluded.modified, raw=excluded.raw, fetched_at=now()""",
                    (vid, full.get("summary"), (full.get("details") or "")[:20000], severity(full), full.get("aliases", []),
                     full.get("published"), full.get("modified"), json.dumps(full)))
            else:
                full = db.q("select raw from advisories where id=%s", (vid,), one=True)["raw"]
            fx = fixed_version(full, comp["ecosystem"], comp["name"])
            row = db.q(
                """insert into findings(component_id,advisory_id,fixed_version) values (%s,%s,%s)
                   on conflict(component_id,advisory_id) do update set last_seen=now(), fixed_version=excluded.fixed_version
                   returning id, (xmax = 0) as inserted""", (comp["id"], vid, fx), one=True)
            if row["inserted"]:
                n_new += 1
                org = db.q("select org_id from hosts where id=%s", (comp["host_id"],), one=True)["org_id"]
                db.q("insert into events(org_id,kind,message,ref) values (%s,'finding',%s,%s)",
                     (org, f"{vid}: {comp['name']} {comp['version']} ({comp['ecosystem']})" + (f" -> fix {fx}" if fx else ""), json.dumps({"finding": row["id"]})))
            propose_for_finding(row["id"])
        if ids:
            db.q("update findings set status='resolved' where component_id=%s and status='open' and not (advisory_id = any(%s))", (comp["id"], ids))
        else:
            db.q("update findings set status='resolved' where component_id=%s and status='open'", (comp["id"],))
        db.q("insert into scan_state(component_id,scanned_at) values (%s,now()) on conflict(component_id) do update set scanned_at=now()", (comp["id"],))
    return n_new


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    db.init_schema()
    with httpx.Client(headers={"User-Agent": "secure.resonator.am worker"}) as client:
        while True:
            try:
                n = scan_once(client)
                if n:
                    log.info("new findings: %d", n)
            except Exception as e:  # keep the stream alive
                log.exception("scan failed: %s", e)
            time.sleep(int(os.environ.get("SCAN_INTERVAL", "60")))


if __name__ == "__main__":
    main()
