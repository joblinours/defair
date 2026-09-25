"""Tests for the rule supply chain: lock, sync, verification, conflicts, assembly."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest
import yaml

from defair.rules.assemble import assemble_signatures, namespace_to_source
from defair.rules.conflicts import sigma_rule_ids, yara_rule_names
from defair.rules.lock import (
    RuleIntegrityError,
    RuleSource,
    load_lock,
    refresh_lock,
    select_members,
)
from defair.rules.sync import sync_rules
from defair.rules.verify import assert_store_intact, is_clean, verify_store

SIGMA_A = "title: A\nid: 11111111-1111-1111-1111-111111111111\nlevel: high\n"
SIGMA_A_OTHER = "title: A changed\nid: 11111111-1111-1111-1111-111111111111\nlevel: low\n"
SIGMA_B = "title: B\nid: 22222222-2222-2222-2222-222222222222\nlevel: medium\n"


def _zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, content in files.items():
            z.writestr(name, content)
    return buf.getvalue()


class FakeGitHub:
    """Serves the GitHub API + archives for refresh_lock / sync_rules."""

    def __init__(self, archives: dict[str, bytes], releases: dict[str, dict] | None = None):
        self.archives = archives
        self.releases = releases or {}

    def __call__(self, url: str) -> bytes:
        if url in self.archives:
            return self.archives[url]
        if url.endswith("/releases/latest"):
            repo = url.split("repos/")[1].removesuffix("/releases/latest")
            return json.dumps(self.releases[repo]).encode()
        if "/commits/" in url:
            return json.dumps({"sha": "c0ffee" * 6 + "abcd"}).encode()
        if "api.github.com/repos/" in url:
            return json.dumps({"license": {"spdx_id": "MIT"}}).encode()
        raise AssertionError(f"unexpected URL {url}")


@pytest.fixture
def world(tmp_path):
    """Two sigma sources (one release, one branch) and one yara source, locked."""
    sha = "c0ffee" * 6 + "abcd"
    release_zip = _zip({
        "rules/windows/a.yml": SIGMA_A,
        "rules/linux/a.yml": SIGMA_B,  # same basename, different folder
    })
    branch_zip = _zip({
        f"extra-{sha}/rules/dup.yml": SIGMA_A,          # duplicate of release a.yml
        f"extra-{sha}/rules/conflict.yml": SIGMA_A_OTHER,
        f"extra-{sha}/.github/ci.yml": "name: ci\n",     # excluded
        f"extra-{sha}/README.md": "x",
    })
    yara_zip = _zip({
        "core.yar": "rule Shared { condition: true }\nrule OnlyCore { condition: true }\n",
    })
    yara_branch_zip = _zip({
        f"yb-{sha}/yara/x.yar": "// rule Commented\nrule Shared { condition: false }\n",
    })

    from defair.rules.lock import sha256_bytes

    fake = FakeGitHub(
        archives={
            "https://example/sigma_core.zip": release_zip,
            f"https://github.com/org/extra/archive/{sha}.zip": branch_zip,
            "https://example/forge.zip": yara_zip,
            f"https://github.com/org/yb/archive/{sha}.zip": yara_branch_zip,
        },
        releases={
            "SigmaHQ/sigma": {"tag_name": "r1", "assets": [{
                "name": "sigma_core.zip",
                "browser_download_url": "https://example/sigma_core.zip",
                "digest": "sha256:" + sha256_bytes(release_zip),
            }]},
            "YARAHQ/yara-forge": {"tag_name": "f1", "assets": [{
                "name": "forge.zip", "browser_download_url": "https://example/forge.zip",
            }]},
        },
    )
    sources = [
        RuleSource(id="forge", engine="yara", repo="YARAHQ/yara-forge", kind="release",
                   asset="forge.zip", extensions=[".yar"], profiles=["precise", "broad"]),
        RuleSource(id="yb", engine="yara", repo="org/yb", kind="branch", branch="main",
                   path_filter="yara/", extensions=[".yar"], profiles=["broad"]),
        RuleSource(id="sigmahq", engine="sigma", repo="SigmaHQ/sigma", kind="release",
                   asset="sigma_core.zip", extensions=[".yml"], profiles=["precise", "broad"],
                   license="DRL-1.1"),
        RuleSource(id="extra", engine="sigma", repo="org/extra", kind="branch", branch="main",
                   extensions=[".yml"], exclude=[".github/"], profiles=["broad"]),
    ]
    lock_dir = tmp_path / "lock"
    lock = refresh_lock(sources, lock_dir, fetch=fake)
    return {"fake": fake, "lock": lock, "lock_dir": lock_dir, "store": tmp_path / "store",
            "tmp": tmp_path}


class TestLock:
    def test_refresh_pins_refs_and_manifests(self, world):
        lock = load_lock(world["lock_dir"])
        assert lock.get("sigmahq").ref == "r1"
        assert lock.get("extra").ref.startswith("c0ffee")
        assert lock.get("sigmahq").license == "DRL-1.1"  # declared license wins
        assert lock.get("extra").license == "MIT"  # from the GitHub API
        manifest = json.loads((world["lock_dir"] / "manifests" / "extra.json").read_text())
        assert set(manifest) == {"rules/dup.yml", "rules/conflict.yml"}  # .github excluded

    def test_refresh_rejects_bad_release_digest(self, world, tmp_path):
        world["fake"].releases["SigmaHQ/sigma"]["assets"][0]["digest"] = "sha256:" + "0" * 64
        sources = [RuleSource(id="s", engine="sigma", repo="SigmaHQ/sigma", kind="release",
                              asset="sigma_core.zip", extensions=[".yml"])]
        with pytest.raises(RuleIntegrityError, match="GitHub digest"):
            refresh_lock(sources, tmp_path / "l2", fetch=world["fake"])

    def test_select_members_rejects_zip_slip(self):
        data = _zip({"../evil.yar": "rule x { condition: true }"})
        source = RuleSource(id="x", engine="yara", repo="a/b", kind="release", extensions=[".yar"])
        with zipfile.ZipFile(io.BytesIO(data)) as z, pytest.raises(RuleIntegrityError):
            select_members(z, source)

    def test_for_profile_order(self, world):
        lock = world["lock"]
        assert [s.id for s in lock.for_profile("broad", "sigma")] == ["sigmahq", "extra"]
        assert [s.id for s in lock.for_profile("precise")] == ["forge", "sigmahq"]
        with pytest.raises(ValueError):
            lock.for_profile("everything")

    def test_packaged_lock_is_consistent(self):
        """The committed lock has a manifest for every source, matching its file count."""
        from defair.rules.lock import load_manifest, load_sources

        lock = load_lock()
        assert {s.id for s in lock.sources} == {s.id for s in load_sources()}
        for s in lock.sources:
            assert len(load_manifest(s.id)) == s.files > 0
            assert s.kind == "release" or len(s.ref) == 40  # branches pinned to a commit


class TestSync:
    def test_sync_preserves_tree(self, world):
        sync_rules(world["store"], world["lock"], world["lock_dir"], fetch=world["fake"])
        store = world["store"]
        # Same basename in two folders: both survive
        assert (store / "sigma/sigmahq/rules/windows/a.yml").read_text() == SIGMA_A
        assert (store / "sigma/sigmahq/rules/linux/a.yml").read_text() == SIGMA_B
        assert not (store / "sigma/extra/.github").exists()
        assert (store / "STORE.json").exists()

    def test_sync_rejects_tampered_release(self, world):
        world["fake"].archives["https://example/sigma_core.zip"] = _zip({"rules/windows/a.yml": "x"})
        with pytest.raises(RuleIntegrityError, match="archive SHA-256"):
            sync_rules(world["store"], world["lock"], world["lock_dir"], fetch=world["fake"])

    def test_sync_rejects_modified_file_in_branch_archive(self, world):
        sha = world["lock"].get("extra").ref
        url = f"https://github.com/org/extra/archive/{sha}.zip"
        world["fake"].archives[url] = _zip({
            f"extra-{sha}/rules/dup.yml": SIGMA_A + "# injected\n",
            f"extra-{sha}/rules/conflict.yml": SIGMA_A_OTHER,
        })
        with pytest.raises(RuleIntegrityError, match="pinned SHA-256"):
            sync_rules(world["store"], world["lock"], world["lock_dir"], fetch=world["fake"],
                       only=["extra"])
        assert not (world["store"] / "sigma" / "extra").exists()  # nothing unverified left

    def test_sync_rejects_extra_file(self, world):
        sha = world["lock"].get("extra").ref
        url = f"https://github.com/org/extra/archive/{sha}.zip"
        world["fake"].archives[url] = _zip({
            f"extra-{sha}/rules/dup.yml": SIGMA_A,
            f"extra-{sha}/rules/conflict.yml": SIGMA_A_OTHER,
            f"extra-{sha}/rules/new.yml": SIGMA_B,
        })
        with pytest.raises(RuleIntegrityError, match="differs from the lock"):
            sync_rules(world["store"], world["lock"], world["lock_dir"], fetch=world["fake"],
                       only=["extra"])

    def test_conflicts_report(self, world):
        result = sync_rules(world["store"], world["lock"], world["lock_dir"], fetch=world["fake"])
        conflicts = json.loads((world["store"] / "CONFLICTS.json").read_text())
        broad = conflicts["broad"]
        assert [d["skipped"]["path"] for d in broad["sigma_duplicates"]] == ["rules/dup.yml"]
        assert [c["skipped"]["path"] for c in broad["sigma_conflicts"]] == ["rules/conflict.yml"]
        assert broad["sigma_conflicts"][0]["kept"]["source"] == "sigmahq"
        assert [c["rule"] for c in broad["yara_name_collisions"]] == ["Shared"]
        assert result["conflicts"]["precise"] == {
            "sigma_duplicates": 0, "sigma_conflicts": 0, "yara_name_collisions": 0,
        }

    def test_index(self, world):
        sync_rules(world["store"], world["lock"], world["lock_dir"], fetch=world["fake"])
        index = json.loads((world["store"] / "INDEX.json").read_text())
        assert index["yara"]["forge"] == {"Shared": "core.yar", "OnlyCore": "core.yar"}
        assert "Commented" not in index["yara"]["yb"]


class TestVerify:
    def test_clean_store(self, world):
        sync_rules(world["store"], world["lock"], world["lock_dir"], fetch=world["fake"])
        assert is_clean(verify_store(world["store"], lock=world["lock"], lock_dir=world["lock_dir"]))

    @pytest.mark.parametrize("tamper", ["modify", "delete", "add"])
    def test_tampered_store_refused(self, world, tamper):
        sync_rules(world["store"], world["lock"], world["lock_dir"], fetch=world["fake"])
        target = world["store"] / "sigma/sigmahq/rules/windows/a.yml"
        if tamper == "modify":
            target.write_text(SIGMA_A + "falsepositives: [everything]\n")
        elif tamper == "delete":
            target.unlink()
        else:
            (target.parent / "backdoor.yml").write_text(SIGMA_B)
        with pytest.raises(RuleIntegrityError, match="scan refused"):
            assert_store_intact(world["store"], ["sigmahq"], world["lock"], world["lock_dir"])


class TestAssemble:
    def test_profile_links_in_lock_order(self, world):
        sync_rules(world["store"], world["lock"], world["lock_dir"], fetch=world["fake"])
        info = assemble_signatures(world["store"], world["tmp"] / "run", "broad", world["lock"],
                                   custom_dirs={"yara": world["tmp"] / "none",
                                                "sigma": world["tmp"] / "none"})
        sigma = sorted(p.name for p in (world["tmp"] / "run/signatures/sigma").iterdir())
        assert sigma == ["00_sigmahq", "01_extra"]
        assert (world["tmp"] / "run/signatures/sigma/00_sigmahq").resolve() == \
            (world["store"] / "sigma/sigmahq").resolve()
        assert info["sources"] == {"yara": ["forge", "yb"], "sigma": ["sigmahq", "extra"]}

    def test_single_engine_leaves_other_empty(self, world):
        sync_rules(world["store"], world["lock"], world["lock_dir"], fetch=world["fake"])
        assemble_signatures(world["store"], world["tmp"] / "run", "precise", world["lock"],
                            engines=("yara",), custom_dirs={})
        assert list((world["tmp"] / "run/signatures/sigma").iterdir()) == []

    def test_custom_rules_linked_and_hashed(self, world):
        sync_rules(world["store"], world["lock"], world["lock_dir"], fetch=world["fake"])
        custom = world["tmp"] / "custom_yara"
        custom.mkdir()
        (custom / "mine.yar").write_text("rule Mine { condition: true }")
        info = assemble_signatures(world["store"], world["tmp"] / "run", "precise", world["lock"],
                                   engines=("yara",), custom_dirs={"yara": custom})
        assert (world["tmp"] / "run/signatures/yara/99_custom").is_symlink()
        assert list(info["custom"]["yara"]) == ["mine.yar"]

    def test_namespace_to_source(self):
        assert namespace_to_source("03_elastic") == "elastic"
        assert namespace_to_source("99_custom") == "custom"
        assert namespace_to_source("default") == "default"


class TestParsers:
    def test_yara_rule_names(self):
        text = "/* rule Hidden { } */\nprivate rule A { condition: true }\nglobal rule B {}\n"
        assert yara_rule_names(text) == ["A", "B"]

    def test_sigma_ids_multi_document(self):
        text = SIGMA_A + "---\n" + SIGMA_B + "  id: nested-not-top-level\n"
        assert sigma_rule_ids(text) == [
            "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222",
        ]


def test_sources_yaml_valid():
    from defair.rules.lock import SOURCES_FILE

    data = yaml.safe_load(Path(SOURCES_FILE).read_text())
    ids = [s["id"] for s in data["sources"]]
    assert len(ids) == len(set(ids))
