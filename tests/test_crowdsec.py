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


# ── Find it ───────────────────────────────────────────────────────────────

SERVER_PROVIDER = '''
def _ssh_args(entry):
    return ["ssh", "-o", "BatchMode=yes", f"{entry['user']}@{entry['host']}"]

def summary(entries, ctx):
    return {"state": "ok", "headline": "", "problems": []}

def details(entries, ctx):
    return []
'''


class FakeRun:
    def __init__(self, answers):
        self.answers, self.calls = answers, []

    def run(self, cmd, timeout=30, env=None):
        self.calls.append((cmd, timeout))
        host = cmd[-2].split("@")[1]
        ans = self.answers[host]
        if isinstance(ans, Exception):
            raise ans
        return subprocess.CompletedProcess(cmd, ans[0], ans[1], "")


@pytest.fixture
def servers(fleet, stand_in, tmp_path):
    srv = stand_in("server", kind="integration", title="Servers (SSH)",
                   entry_schema={"host": "str", "user": "str", "sudo": "bool?"})
    (srv.path / "provider.py").write_text(SERVER_PROVIDER)
    addons.set_entry(srv, "web1", {"host": "203.0.113.5", "user": "me", "sudo": True})
    addons.set_entry(srv, "web2", {"host": "203.0.113.6", "user": "me"})
    addons.set_entry(srv, "gone", {"host": "203.0.113.7", "user": "me"})
    addons.set_entry(srv, "nodocker", {"host": "203.0.113.8", "user": "me"})
    return srv


def test_find_it_lists_crowdsec_containers_on_known_servers(addon, servers):
    mod = addons.provider(addon)
    fake = FakeRun({"203.0.113.5": (0, "crowdsec crowdsecurity/crowdsec:v1.6.3\ntraefik traefik:v3.1\n"),
                    "203.0.113.6": (0, "security docker.io/crowdsecurity/crowdsec@sha256:abc\n"
                                       "bouncer fbonalair/traefik-crowdsec-bouncer:latest\n"),
                    "203.0.113.7": subprocess.TimeoutExpired("ssh", 15),
                    "203.0.113.8": (127, "")})
    got = mod.discover({}, fake)
    assert got == [{"title": "CrowdSec on web1 (container crowdsec)", "name": "web1",
                    "fill": {"server": "web1", "container": "crowdsec"}},
                   {"title": "CrowdSec on web2 (container security)", "name": "web2-security",
                    "fill": {"server": "web2", "container": "security"}}]
    cmds = {c[-2]: c[-1] for c, _ in fake.calls}
    assert cmds["me@203.0.113.5"].startswith("sudo -n docker ps") and cmds["me@203.0.113.6"].startswith("docker ps")
    assert all(t <= 15 for _, t in fake.calls)


def test_find_it_leaves_out_installs_already_added(addon, servers):
    mod = addons.provider(addon)
    fake = FakeRun({"203.0.113.5": (0, "crowdsec crowdsecurity/crowdsec:latest\n"),
                    "203.0.113.6": (0, "security crowdsecurity/crowdsec\n"),
                    "203.0.113.7": (255, ""), "203.0.113.8": (255, "")})
    got = mod.discover({"old": {"server": "web1"}, "other": {"server": "web2", "container": "security"}}, fake)
    assert got == []


def test_find_it_through_core_shows_on_the_page(addon, servers, monkeypatch):
    from hisho import connect
    fake = FakeRun({"203.0.113.5": (0, "crowdsec crowdsecurity/crowdsec:v1\n"), "203.0.113.6": (0, ""),
                    "203.0.113.7": (255, ""), "203.0.113.8": (255, "")})
    monkeypatch.setattr(addons.Context, "run", lambda self, cmd, timeout=30, env=None: fake.run(cmd, timeout, env))
    connect._cache.clear()
    got = connect.found(addon, nets=[], refresh=True)
    assert [f["title"] for f in got["found"]] == ["CrowdSec on web1 (container crowdsec)"]
    assert addons.view(addon, data={})["discover"] is True
