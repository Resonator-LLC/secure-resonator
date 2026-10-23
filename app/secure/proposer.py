"""Turns a finding into a proposal: concrete steps a human approves and an agent executes.
Rule engine today; an LLM proposer (paid via Resonator tokens) can replace `steps_for` per org."""
import json
from . import db

DISTRO_CMDS = {
    "Debian": "apt-get install --only-upgrade -y {name}",
    "Ubuntu": "apt-get install --only-upgrade -y {name}",
    "Alpine": "apk upgrade {name}",
}
LANG_CMDS = {
    "npm": "npm install {name}@{fixed} && npm audit",
    "PyPI": "pip install '{name}>={fixed}'",
    "crates.io": "cargo update -p {name} --precise {fixed}",
    "Go": "go get {name}@v{fixed} && go mod tidy",
    "RubyGems": "bundle update {name}",
    "Maven": "update {name} to {fixed} in pom.xml / build.gradle, then rebuild",
}


def steps_for(f):
    eco = f["ecosystem"].split(":")[0]
    fixed = f["fixed_version"]
    if eco in DISTRO_CMDS:
        cmd = DISTRO_CMDS[eco].format(name=f["name"])
        return [
            {"kind": "shell", "run": "apt-get update" if eco != "Alpine" else "apk update", "note": "refresh package index"},
            {"kind": "shell", "run": cmd, "note": f"upgrade to {fixed}" if fixed else "upgrade to the distro's fixed build"},
            {"kind": "verify", "run": f"dpkg -s {f['name']} | grep Version" if eco != "Alpine" else f"apk info {f['name']}", "expect": fixed},
            {"kind": "manual", "note": "restart services that link this package (needrestart -r a on Debian/Ubuntu)"},
        ], True
    if eco in LANG_CMDS and fixed:
        return [
            {"kind": "shell", "run": LANG_CMDS[eco].format(name=f["name"], fixed=fixed), "note": "upgrade dependency", "cwd": "<project root>"},
            {"kind": "verify", "note": f"lockfile now pins {f['name']} {fixed}; run the test suite"},
            {"kind": "manual", "note": "rebuild and redeploy the affected service"},
        ], True
    return [{"kind": "manual", "note": "no fixed version published yet: review the advisory, consider mitigations or removal"}], False


def propose_for_finding(finding_id: int):
    f = db.q(
        """select f.id, f.fixed_version, c.ecosystem, c.name, c.version, c.host_id, h.org_id, a.id advisory_id, a.summary, a.severity
           from findings f join components c on c.id=f.component_id join hosts h on h.id=c.host_id join advisories a on a.id=f.advisory_id
           where f.id=%s and f.status='open'""", (finding_id,), one=True)
    if not f or db.q("select 1 from proposals where finding_id=%s", (finding_id,), one=True):
        return
    steps, actionable = steps_for(f)
    title = f"{'Upgrade' if actionable else 'Review'} {f['name']} {f['version']} ({f['advisory_id']})"
    rationale = f"{f['advisory_id']}" + (f" [{f['severity']}]" if f["severity"] else "") + f": {f['summary'] or 'see advisory'}." + \
        (f" Fixed in {f['fixed_version']}." if f["fixed_version"] else " No fixed version yet.")
    db.q("insert into proposals(org_id,host_id,finding_id,title,rationale,steps) values (%s,%s,%s,%s,%s,%s) on conflict(finding_id) do nothing",
         (f["org_id"], f["host_id"], finding_id, title, rationale, json.dumps(steps)))
