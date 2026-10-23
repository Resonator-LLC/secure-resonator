"""Inventory ingestion. Accepts {host, os, source, components:[{ecosystem,name,version,purl?}]}.
Ecosystem names follow OSV (Debian, Ubuntu, Alpine, npm, PyPI, crates.io, Go, Maven, RubyGems, ...)."""
from . import db

OSV_ECOSYSTEMS = {"debian": "Debian", "ubuntu": "Ubuntu", "alpine": "Alpine", "npm": "npm", "pypi": "PyPI", "crates.io": "crates.io", "cargo": "crates.io",
                  "go": "Go", "maven": "Maven", "rubygems": "RubyGems", "nuget": "NuGet", "packagist": "Packagist", "hex": "Hex", "pub": "Pub", "docker": "Docker", "oci": "OCI"}


def norm_eco(e: str, os_name: str = "") -> str:
    e = (e or "").strip()
    base = OSV_ECOSYSTEMS.get(e.lower(), e)
    # OSV distro ecosystems carry the release: "Debian:12", "Ubuntu:24.04", "Alpine:v3.20"
    if base in ("Debian", "Ubuntu", "Alpine") and ":" not in e:
        rel = _release(os_name, base)
        if rel:
            return f"{base}:{rel}"
    return base if ":" not in e else e


def _release(os_name, base):
    import re
    m = re.search(r"(\d+(?:\.\d+)?)", os_name or "")
    if not m:
        return None
    v = m.group(1)
    if base == "Debian":
        return v.split(".")[0]
    if base == "Alpine":
        return "v" + ".".join(v.split(".")[:2])
    return v


def ingest_inventory(org_id: int, body: dict, source: str = "agent") -> int:
    host = (body.get("host") or "").strip()
    if not host:
        raise ValueError("host required")
    os_name = (body.get("os") or "")[:120]
    with db.conn() as c:
        h = c.execute(
            """insert into hosts(org_id,name,os,source,last_report_at) values (%s,%s,%s,%s,now())
               on conflict(org_id,name) do update set os=excluded.os, source=excluded.source, last_report_at=now() returning id""",
            (org_id, host, os_name, source)).fetchone()
        hid = h["id"]
        seen = []
        for comp in body.get("components") or []:
            eco = norm_eco(comp.get("ecosystem"), os_name)
            name, ver = (comp.get("name") or "").strip(), (comp.get("version") or "").strip()
            if not (eco and name and ver):
                continue
            row = c.execute(
                """insert into components(host_id,ecosystem,name,version,purl) values (%s,%s,%s,%s,%s)
                   on conflict(host_id,ecosystem,name,version) do update set purl=coalesce(excluded.purl,components.purl) returning id""",
                (hid, eco, name[:200], ver[:100], comp.get("purl"))).fetchone()
            seen.append(row["id"])
        # components no longer reported are removed (their findings cascade)
        if seen:
            c.execute("delete from components where host_id=%s and not (id = any(%s))", (hid, seen))
        else:
            c.execute("delete from components where host_id=%s", (hid,))
    return len(seen)
