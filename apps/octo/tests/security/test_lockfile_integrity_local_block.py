"""A short local-block term inside a lockfile's integrity hash is not a finding.

Base64 / hex integrity hashes contain any short letter sequence by chance, so
a 3-character term (case-insensitive) hit a fresh npm lockfile and blocked a
dependency upgrade. The exemption is narrow: only a match wholly inside an
integrity hash of a dependency lockfile; the same term elsewhere in the
lockfile, or the same hash text in any other file, is still a finding.
"""
from __future__ import annotations

from apps.octo.tests.security import hostile

TERM = "q" + "x7"  # a synthetic 3-character term, built at run time
HASH = "sha512-" + "AbC" + TERM.upper() + "dEf0123456789+/ghIJKLmnopQRstuVWxyz" * 2 + "=="


def _local(tmp_path):
    ss = hostile._scanner()
    block = tmp_path / "block"
    block.write_text(TERM + "\n")
    return ss, ss.load_local_block(block)


def _detectors(findings):
    return [f.detector for f in findings]


def test_term_inside_an_npm_integrity_hash_is_ignored(tmp_path):
    ss, local = _local(tmp_path)
    text = '{\n  "node_modules/left-pad": {\n    "integrity": "' + HASH + '"\n  }\n}\n'
    assert "local-block" not in _detectors(ss.scan_text("apps/web/package-lock.json", text, publish=True, local=local))


def test_term_in_a_lockfile_package_name_is_still_found(tmp_path):
    ss, local = _local(tmp_path)
    text = '{\n  "node_modules/' + TERM + '-utils": {\n    "integrity": "' + HASH + '"\n  }\n}\n'
    assert "local-block" in _detectors(ss.scan_text("apps/web/package-lock.json", text, publish=True, local=local))


def test_same_hash_in_a_normal_file_is_still_found(tmp_path):
    ss, local = _local(tmp_path)
    text = 'value = "' + HASH + '"\n'
    assert "local-block" in _detectors(ss.scan_text("apps/web/src/data.ts", text, publish=True, local=local))


def test_yarn_poetry_and_cargo_hash_forms(tmp_path):
    ss, local = _local(tmp_path)
    assert "local-block" not in _detectors(ss.scan_text("yarn.lock", "  integrity " + HASH + "\n", publish=True, local=local))
    # hex hashes can only contain hex digits: use a hex-shaped synthetic term
    term_hex = "c" + "0f"
    block = tmp_path / "block-hex"
    block.write_text(term_hex + "\n")
    local_hex = ss.load_local_block(block)
    hexh = ("ab" + term_hex + "d9") * 11
    hexh = hexh[:64]
    for name, text in {
        "poetry.lock": 'hash = "sha256:' + hexh + '"\n',
        "uv.lock": 'hash = "sha256:' + hexh + '"\n',
        "Cargo.lock": 'checksum = "' + hexh + '"\n',
    }.items():
        assert "local-block" not in _detectors(ss.scan_text(name, text, publish=True, local=local_hex)), name
    # ...and the same hex in a source file is still found
    assert "local-block" in _detectors(ss.scan_text("src/x.py", 'h = "' + hexh + '"\n', publish=True, local=local_hex))


def test_the_version_is_10():
    assert hostile._scanner().GUARDRAILS_VERSION == 10
