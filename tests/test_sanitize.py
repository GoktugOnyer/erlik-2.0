"""Tests for command sanitization — the target-host rewrite that makes tools
inside the kali-tools container actually reach the target, plus the nuclei and
invented-flag fixes. All derived from real run-log failures."""

import orchestrator.tool_executor as te


def _s(monkeypatch, cmd, target="http://localhost:3000",
       native=False, legacy="", gw="host.docker.internal"):
    monkeypatch.setattr(te, "ERLIK_NATIVE", native)
    monkeypatch.setattr(te, "LEGACY_DOCKER_TARGET_HOST", legacy)
    monkeypatch.setattr(te, "DOCKER_HOST_GATEWAY", gw)
    return te._sanitize_command(cmd, target)


class TestTargetRewrite:
    def test_juiceshop_alias_to_gateway(self, monkeypatch):
        # The model's juice-shop bias must go to the reachable host, NOT to
        # localhost (the old bug — localhost is the container from inside docker).
        assert "host.docker.internal:3000" in _s(monkeypatch, "curl -sI http://juice-shop:3000")

    def test_localhost_url_to_gateway(self, monkeypatch):
        out = _s(monkeypatch, "gobuster dir -u http://localhost:3000 -w /w")
        assert "http://host.docker.internal:3000" in out

    def test_bare_localhost_host_to_gateway(self, monkeypatch):
        out = _s(monkeypatch, "nmap -sV localhost -p 3000")
        assert "host.docker.internal" in out and "localhost" not in out

    def test_127_to_gateway(self, monkeypatch):
        assert "host.docker.internal" in _s(monkeypatch, "curl -v http://127.0.0.1:3000")

    def test_native_mode_keeps_localhost(self, monkeypatch):
        out = _s(monkeypatch, "curl http://localhost:3000", native=True)
        assert "localhost:3000" in out and "host.docker.internal" not in out

    def test_legacy_override_wins(self, monkeypatch):
        out = _s(monkeypatch, "curl http://localhost:3000", legacy="juice-shop")
        assert "juice-shop:3000" in out

    def test_remote_target_unchanged(self, monkeypatch):
        out = _s(monkeypatch, "nmap scanme.example.org", target="http://scanme.example.org")
        assert "scanme.example.org" in out and "host.docker.internal" not in out

    def test_wordlist_path_never_touched(self, monkeypatch):
        out = _s(monkeypatch, "gobuster dir -u http://localhost:3000 -w /usr/share/dirb/wordlists/common.txt")
        assert "/usr/share/dirb/wordlists/common.txt" in out


class TestNucleiFix:
    def test_bad_category_templates_stripped_tags_added(self, monkeypatch):
        out = _s(monkeypatch, "nuclei -u http://localhost:3000 -t cves/ -t web-dirs/ -t exposures/")
        assert "-t cves/" not in out and "-t web-dirs/" not in out
        assert "-tags" in out

    def test_bad_specific_template_stripped(self, monkeypatch):
        out = _s(monkeypatch, "nuclei -u http://localhost:3000 -t cves/2019/cve-2019-14687.yaml")
        assert "cve-2019-14687" not in out and "-tags" in out

    def test_absolute_template_path_kept(self, monkeypatch):
        out = _s(monkeypatch, "nuclei -u http://localhost:3000 -t /root/nuclei-templates/x.yaml")
        assert "/root/nuclei-templates/x.yaml" in out

    def test_no_selector_gets_default_tags(self, monkeypatch):
        out = _s(monkeypatch, "nuclei -u http://localhost:3000")
        assert "-tags" in out


class TestInventedFlags:
    def test_arjun_fuzzer_stripped(self, monkeypatch):
        assert "--fuzzer" not in _s(monkeypatch, "arjun -u http://localhost:3000 --fuzzer")

    def test_arjun_include_js_stripped(self, monkeypatch):
        assert "--include-js" not in _s(monkeypatch, "arjun -u http://localhost:3000/login --include-js")

    def test_crlfuzz_batch_stripped(self, monkeypatch):
        assert "batch" not in _s(monkeypatch, "crlfuzz -u http://localhost:3000/x --batch")

    def test_dalfox_depth_stripped(self, monkeypatch):
        assert "--depth" not in _s(monkeypatch, "dalfox url http://localhost:3000/p --depth 2")
