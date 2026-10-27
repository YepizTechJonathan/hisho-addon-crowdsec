"""CrowdSec integration for Hisho (see addon.yaml). Runs inside Core; reads cscli over SSH through
the Servers (SSH) integration's connection (same pinned host key)."""
from __future__ import annotations

import json
import shlex
import subprocess
import time
from datetime import datetime, timezone
from typing import Any

COMMANDS = {"decisions": "decisions list", "alerts": "alerts list --since 24h", "bouncers": "bouncers list",
            "acquisition": "metrics show acquisition", "appsec": "metrics show appsec"}
_last_reads: dict[str, tuple[float, int]] = {}   # entry -> (when, lines read) to see if reading stalls


def _server(entry: dict[str, Any]) -> tuple[Any, dict[str, Any]]:
    from hisho import addons
    srv = addons.get("server")
    target = addons.entries(srv).get(str(entry["server"]))
    if target is None:
        raise RuntimeError(f"no server named {entry['server']} on the Servers (SSH) page")
    return addons.provider(srv), target


def read(entry: dict[str, Any]) -> dict[str, Any]:
    mod, target = _server(entry)
    mod._trust(target)
    c = shlex.quote(str(entry.get("container") or "crowdsec"))
    script = "".join(f"echo '##{k}'; docker exec {c} cscli {v} -o json 2>/dev/null; echo\n" for k, v in COMMANDS.items())
    if target.get("sudo"):
        script = script.replace("docker exec", "sudo -n docker exec")
    res = subprocess.run(mod._ssh_args(target) + ["bash -s"], input=script, capture_output=True, text=True, timeout=60)
    out: dict[str, Any] = {}
    for part in res.stdout.split("##")[1:]:
        key, _, body = part.partition("\n")
        try:
            out[key.strip()] = json.loads(body.strip() or "null")
        except ValueError:
            out[key.strip()] = None
    if all(v is None for v in out.values()):
        raise RuntimeError((res.stderr.strip() or "CrowdSec didn't answer (is the container running?)")[-200:])
    return out


def _age(stamp: str | None) -> float | None:
    try:
        return time.time() - datetime.fromisoformat(str(stamp).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return None


def facts(name: str, d: dict[str, Any]) -> dict[str, Any]:
    decisions = [x for a in d.get("decisions") or [] for x in a.get("decisions") or []]
    alerts = d.get("alerts") or []
    bouncers = d.get("bouncers") or []
    acq = (d.get("acquisition") or {}).get("acquisition") or {}
    reads = sum(int(v.get("reads") or 0) for k, v in acq.items() if k.startswith("file:"))
    waf = sum(int(v.get("blocked") or 0) for v in ((d.get("appsec") or {}).get("appsec-engine") or {}).values())
    prev = _last_reads.get(name)
    stalled = prev is not None and reads <= prev[1] and time.time() - prev[0] > 900
    if prev is None or reads > prev[1]:
        _last_reads[name] = (time.time(), reads)
    pulls = [(_age(b.get("last_pull")), b) for b in bouncers if not b.get("revoked")]
    return {"bans": decisions, "alerts": alerts, "bouncers": pulls, "reads": reads, "waf_blocked": waf,
            "stalled": stalled}


def summary(entries: dict[str, dict[str, Any]], ctx: Any) -> dict[str, Any]:
    problems, bans, waf = [], 0, 0
    for name, entry in entries.items():
        try:
            f = facts(name, read(entry))
        except Exception as exc:  # noqa: BLE001
            problems.append({"entry": name, "severity": "critical", "title": f"CrowdSec on {entry['server']} isn't answering",
                             "detail": f"{str(exc)[:160]}. Sites are unprotected until it's back."})
            continue
        bans += len(f["bans"])
        waf += f["waf_blocked"]
        if not f["bouncers"]:
            problems.append({"entry": name, "severity": "critical", "title": f"CrowdSec on {entry['server']} has no bouncer",
                             "detail": "It detects attacks but nothing blocks them. Run 'CrowdSec Enable' in Semaphore."})
        elif all(age is None or age > 600 for age, _ in f["bouncers"]):
            problems.append({"entry": name, "severity": "warn", "title": f"CrowdSec's bouncer on {entry['server']} stopped syncing",
                             "detail": "New bans don't reach Traefik. Check Traefik is running; the off switch is 'CrowdSec Disable'."})
        if f["reads"] == 0 or f["stalled"]:
            problems.append({"entry": name, "severity": "warn", "title": f"CrowdSec on {entry['server']} isn't reading logs",
                             "detail": "It can't see attacks. Check its acquis.yaml and Traefik's access log."})
    return {"state": "down" if any(p["severity"] == "critical" for p in problems) else "warn" if problems else "ok",
            "headline": f"{bans} IP{'s' * (bans != 1)} banned · {waf} attack requests blocked since restart",
            "problems": problems}


def details(entries: dict[str, dict[str, Any]], ctx: Any) -> list[dict[str, Any]]:
    out = []
    for name, entry in entries.items():
        try:
            d = read(entry)
            f = facts(name, d)
        except Exception as exc:  # noqa: BLE001
            out.append({"title": name, "entry": name, "state": "down", "facts": [str(exc)[:200]], "items": []})
            continue
        items = []
        for age, b in f["bouncers"]:
            items.append({"id": f"b-{b.get('name')}", "name": f"Bouncer {b.get('name')} ({b.get('version')})",
                          "state": "up" if age is not None and age < 600 else "down",
                          "facts": [f"last sync {int(age)}s ago" if age is not None else "never synced"], "actions": []})
        rules = ((d.get("appsec") or {}).get("appsec-rule") or {})
        top = sorted(((r, v.get("triggered", 0)) for eng in rules.values() for r, v in eng.items()), key=lambda x: -x[1])
        items.append({"id": "waf", "name": f"Web firewall: {f['waf_blocked']} requests blocked", "state": "up",
                      "facts": [f"{r.split('/')[-1]}: {n}" for r, n in top[:10]] or ["nothing blocked yet"], "actions": []})
        for x in f["bans"][:30]:
            items.append({"id": f"d-{x.get('id')}", "name": f"Banned {x.get('value')}", "state": "warn",
                          "facts": [f"{str(x.get('scenario')).split('/')[-1]} · {x.get('duration')} left · {x.get('origin')}"],
                          "actions": [{"id": "unban", "label": "unban",
                                       "confirm": f"Unban {x.get('value')}? It can reach your sites again until CrowdSec catches it again."}]})
        for a in (f["alerts"] or [])[:15]:
            items.append({"id": f"a-{a.get('id')}", "name": str(a.get("message") or a.get("scenario"))[:100],
                          "state": "off", "facts": [str(a.get("created_at"))[:16].replace("T", " ")], "actions": []})
        out.append({"title": f"{name} (on {entry['server']})", "entry": name, "state": "ok",
                    "facts": [f"{f['reads']} log lines read since restart", f"{len(f['bans'])} active bans · "
                              f"{len(f['alerts'])} alerts in 24 h"] + ([entry["note"]] if entry.get("note") else []),
                    "items": items})
    return out


def test(entry: dict[str, Any], ctx: Any) -> dict[str, Any]:
    try:
        f = facts("_test", read(entry))
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)[:200]}
    return {"ok": True, "message": f"Connected: {len(f['bouncers'])} bouncer(s), {f['reads']} log lines read, "
                                   f"{len(f['bans'])} active bans"}


def _cscli(entry: dict[str, Any], args: str) -> subprocess.CompletedProcess:
    mod, target = _server(entry)
    mod._trust(target)
    c = shlex.quote(str(entry.get("container") or "crowdsec"))
    sudo = "sudo -n " if target.get("sudo") else ""
    return subprocess.run(mod._ssh_args(target) + [f"{sudo}docker exec {c} cscli {args}"], capture_output=True, text=True, timeout=60)


def act(entries: dict[str, dict[str, Any]], ctx: Any, entry: str, item: str, action: str) -> dict[str, Any]:
    target = entries.get(entry)
    if target is None:
        return {"ok": False, "error": f"no CrowdSec install {entry}"}
    if action == "unban" and item.startswith("d-") and item[2:].isdigit():
        res = _cscli(target, f"decisions delete --id {int(item[2:])}")
        if res.returncode != 0:
            return {"ok": False, "error": (res.stderr.strip() or res.stdout.strip())[-200:]}
        return {"ok": True, "message": f"Unbanned (decision {item[2:]}); {res.stdout.strip()[-120:] or 'done'}"}
    return {"ok": False, "error": f"unknown action {action}"}
