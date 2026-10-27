"""CrowdSec add-on tests. Run with Hisho's venv at the repository's top:
~/code/hisho/.venv/bin/python -m pytest -q"""
import json
import subprocess
from pathlib import Path

import pytest
import yaml

from hisho import addon_store, addons
from hisho.addon_testing import AUTH, TOKEN, Recorder

HERE = Path(__file__).resolve().parents[1]


def ctx_for(addon):
    return addons.Context(addon, resolve=lambda name: f"value-of-{name}")


def test_manifest_is_valid_and_readme_matches(addon):
    assert addons.validate_manifest(addon.manifest) == []
    assert addon_store.readme_problems(HERE) == []


def test_the_crowdsec_integration_reports_blocking_and_flags_a_dead_bouncer(fleet, monkeypatch):
    cs = addons.get("crowdsec")
    mod = addons.provider(cs)
    now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()
    data = {"decisions": [{"decisions": [{"id": 1, "value": "203.0.113.9", "scenario": "crowdsecurity/http-probing",
                                          "duration": "3h", "origin": "crowdsec"}]}],
            "alerts": [{"id": 9, "message": "WAF block: vpatch-env-access", "created_at": now}],
            "bouncers": [{"name": "traefik-bouncer", "version": "v1.7.1", "last_pull": now, "revoked": False}],
            "acquisition": {"acquisition": {"file:/var/log/traefik/access.log": {"reads": 50}}},
            "appsec": {"appsec-engine": {"traefik-appsec": {"blocked": 7}},
                       "appsec-rule": {"traefik-appsec": {"crowdsecurity/vpatch-env-access": {"triggered": 7}}}}}
    monkeypatch.setattr(mod, "read", lambda entry: data)
    s = mod.summary({"offsite": {"server": "offsite"}}, None)
    assert s["headline"] == "1 IP banned · 7 attack requests blocked since restart" and s["problems"] == []
    data["bouncers"] = []
    data["acquisition"] = {"acquisition": {}}
    titles = [p["title"] for p in mod.summary({"offsite": {"server": "offsite"}}, None)["problems"]]
    assert titles == ["CrowdSec on offsite has no bouncer", "CrowdSec on offsite isn't reading logs"]


def test_the_crowdsec_unban_button_deletes_that_decision_only(fleet, monkeypatch):
    mod = addons.provider(addons.get("crowdsec"))
    ran = []
    monkeypatch.setattr(mod, "_cscli", lambda entry, args: ran.append(args) or __import__("subprocess").CompletedProcess([], 0, "1 decision(s) deleted", ""))
    entries = {"offsite": {"server": "offsite"}}
    assert mod.act(entries, None, "offsite", "d-42", "unban")["ok"]
    assert ran == ["decisions delete --id 42"]
    assert not mod.act(entries, None, "offsite", "d-42; rm", "unban")["ok"]
    assert not mod.act(entries, None, "nope", "d-1", "unban")["ok"]
