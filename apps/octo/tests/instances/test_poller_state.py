"""`adapter_poller_state` helpers: one row per key, and the batched writer a
poller with many small parts of state uses (NextDNS: one row per profile).

Pinned: `save_many` writes every given row and deletes the given keys in ONE
transaction (all or nothing: a value over the bound writes nothing);
`load_prefix` reads back exactly the keys with that prefix (a `_` or `%` in
the prefix is literal, never a LIKE wildcard); `dumps` is the stored text.
"""
from __future__ import annotations

from apps.octo.instances import poller_state
from apps.octo.tests.instances.test_manager import bedrock_root  # noqa: F401


def test_save_many_writes_and_deletes_in_one_transaction(bedrock_root):  # noqa: F811
    assert poller_state.save_many(1, {"x:p:a": {"n": 1}, "x:p:b": {"n": 2}, "x": {"v": 2}})
    assert poller_state.load_prefix(1, "x:p:") == {"x:p:a": {"n": 1}, "x:p:b": {"n": 2}}
    assert poller_state.save_many(1, {"x:p:a": {"n": 3}}, delete=["x:p:b"])
    assert poller_state.load_prefix(1, "x:p:") == {"x:p:a": {"n": 3}}
    assert poller_state.load(1, "x") == {"v": 2}
    # Another instance's rows are never read.
    assert poller_state.save_many(2, {"x:p:a": {"n": 9}})
    assert poller_state.load_prefix(1, "x:p:") == {"x:p:a": {"n": 3}}
    # Nothing to do is a success, not a write.
    assert poller_state.save_many(1, {}, delete=[])


def test_a_value_over_the_bound_writes_nothing(bedrock_root, monkeypatch):  # noqa: F811
    monkeypatch.setattr(poller_state, "MAX_VALUE_BYTES", 64)
    assert poller_state.save_many(1, {"k1": {"ok": 1}})
    assert not poller_state.save_many(1, {"k1": {"ok": 2}, "k2": {"big": "y" * 100}})
    assert poller_state.load(1, "k1") == {"ok": 1} and poller_state.load(1, "k2") is None


def test_the_prefix_is_literal(bedrock_root):  # noqa: F811
    assert poller_state.save_many(1, {"a_b:1": 1, "axb:2": 2, "a%b:3": 3})
    assert poller_state.load_prefix(1, "a_b:") == {"a_b:1": 1}
    assert poller_state.load_prefix(1, "a%b:") == {"a%b:3": 3}
    assert poller_state.dumps({"b": 1, "a": [1, 2]}) == '{"a":[1,2],"b":1}'
