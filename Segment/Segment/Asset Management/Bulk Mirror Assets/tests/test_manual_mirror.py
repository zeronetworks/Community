"""Unit and mock-transport tests for manual_mirror_assets.py."""

from __future__ import annotations

import argparse
import asyncio
import csv
import importlib.util
import json
import logging
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Awaitable, Callable

import httpx
import pytest

WORKTREE_DIR = Path(__file__).resolve().parent.parent
if str(WORKTREE_DIR) not in sys.path:
    sys.path.insert(0, str(WORKTREE_DIR))

_spec = importlib.util.spec_from_file_location(
    "manual_mirror_assets", WORKTREE_DIR / "manual_mirror_assets.py"
)
mma = importlib.util.module_from_spec(_spec)
sys.modules["manual_mirror_assets"] = mma
_spec.loader.exec_module(mma)

BASE_URL = "https://zn.test/api/v1"
NOW_MS = 1_800_000_000_000
SRC = "a:w:SRC00001"
DST = "a:w:DST00001"
PAIR = mma.AssetPair(src_id=SRC, src_name="SrcHost", dst_id=DST, dst_name="DstHost")
FORBIDDEN_BODY_KEYS = {
    "id", "context", "name", "direction", "ruleclass", "createdAt", "createdBy",
    "updatedAt", "updatedBy", "approvedAt", "approvedBy", "activitiesCount",
    "localEntitySuccessor", "parentId", "parentType", "mirrorSwitchRuleId",
}


def make_rule(
    rule_id: str,
    local: str,
    remote: list[str],
    *,
    action: int = 1,
    state: int = 1,
    excluded: list[str] | None = None,
    expires: int | None = None,
    description: str | None = "orig desc",
    ipsec: int | None = 2,
) -> dict[str, Any]:
    """Build a rule dict shaped like the API response (including forbidden fields)."""
    rule: dict[str, Any] = {
        "id": rule_id,
        "action": action,
        "state": state,
        "localEntityId": local,
        "remoteEntityIdsList": remote,
        "localProcessesList": ["*"],
        "portsList": [{"protocolType": 6, "ports": "445"}],
        "servicesList": ["svc"],
        "excludedLocalIdsList": excluded if excluded is not None else [],
        "expiresAt": expires,
        "description": description,
        "direction": 1,
        "ruleclass": 2,
        "createdAt": 1,
        "createdBy": {"id": "x"},
        "activitiesCount": 3,
        "parentId": "p",
        "mirrorSwitchRuleId": "m",
        "srcUsersList": None,
        "sourceInfos": {"x": 1},
    }
    if ipsec is not None:
        rule["ipSecOpt"] = ipsec
    return rule


SECONDARY_ROUTES = (
    "reactive-policies", "identity", "identity-rules", "rpc-rules",
    "switch-rules", "external-access-policies",
)


def json_ok(items: list[Any], **extra: Any) -> httpx.Response:
    """A 200 response with an items list."""
    return httpx.Response(200, json={"items": items, **extra})


def route_path(request: httpx.Request) -> str:
    """Request path relative to the API base (no /api/v1 prefix)."""
    return request.url.path[len("/api/v1"):]


class Recorder:
    """Wraps a mock handler and records every request it receives."""

    def __init__(self, handler: Callable[[httpx.Request], httpx.Response]) -> None:
        self.handler = handler
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.handler(request)

    @property
    def methods(self) -> set[str]:
        return {r.method for r in self.requests}


def make_client(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.AsyncClient:
    """Create an AsyncClient on the mock transport."""
    return httpx.AsyncClient(base_url=BASE_URL, transport=httpx.MockTransport(handler))


def run_with_client(
    handler: Callable[[httpx.Request], httpx.Response],
    fn: Callable[[httpx.AsyncClient], Awaitable[Any]],
) -> Any:
    """Run an async function with a mock client and return its result."""

    async def runner() -> Any:
        async with make_client(handler) as client:
            return await fn(client)

    return asyncio.run(runner())


def default_opts(**overrides: Any) -> mma.RunOptions:
    """RunOptions with a fixed clock, overridable per test."""
    opts = mma.RunOptions(now_ms=NOW_MS)
    for key, value in overrides.items():
        setattr(opts, key, value)
    return opts


# ---------------------------------------------------------------------------
# Fake Zero Networks backend used for the dry-run test
# ---------------------------------------------------------------------------


class FakeZN:
    """Serves read endpoints from in-memory data and records every method."""

    def __init__(self, assets: dict[str, dict], rules: dict[tuple[str, str], list[dict]],
                 groups: dict[str, list[dict]], group_parents: dict[str, list[dict]] | None = None):
        self.assets = assets
        self.rules = rules
        self.groups = groups
        self.group_parents = group_parents or {}
        self.methods: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.methods.append(request.method)
        if request.method != "GET":
            return httpx.Response(405, json={"error": "write attempted in test"})
        path = request.url.path[len("/api/v1"):]
        parts = path.strip("/").split("/")
        if parts[0] == "assets" and len(parts) == 2:
            asset = self.assets.get(parts[1])
            if asset is None:
                return httpx.Response(404, json={"error": "not found"})
            return httpx.Response(200, json={"entity": asset})
        if parts[0] == "assets" and parts[2:] == ["ancestors"]:
            return httpx.Response(200, json={"items": self.groups.get(parts[1], [])})
        if parts[0] == "groups" and parts[-1] == "ancestors":
            return httpx.Response(200, json={"items": self.group_parents.get(parts[2], [])})
        if parts[:2] == ["protection", "rules"]:
            entity = json.loads(request.url.params["entityParams"])
            items = self.rules.get((parts[2], entity["id"]), [])
            offset = int(request.url.params["_offset"])
            limit = int(request.url.params["_limit"])
            return httpx.Response(200, json={"items": items[offset:offset + limit]})
        # Secondary-category list endpoints: empty unless a test supplies data.
        if parts[0] == "assets" and len(parts) > 2 and parts[2] == "protection":
            return httpx.Response(200, json={"items": []})
        if parts[0] == "protection" and parts[1] in SECONDARY_ROUTES:
            return httpx.Response(200, json={"items": []})
        if parts[:2] == ["settings", "connect"]:
            return httpx.Response(200, json={"items": []})
        return httpx.Response(404, json={"error": f"no route {path}"})


def asset(asset_id: str, **fields: Any) -> dict[str, Any]:
    """Build an asset entity dict."""
    base = {"id": asset_id, "name": asset_id, "operatingSystem": "Windows",
            "source": 1, "protectionState": "segmented", "inactiveSince": None,
            "inactiveReason": None}
    base.update(fields)
    return base


# ---------------------------------------------------------------------------
# classify_rule
# ---------------------------------------------------------------------------


def test_classify_owner_remote_both_and_group_inherited() -> None:
    owner = make_rule("r1", SRC, ["a:w:X"])
    remote = make_rule("r2", "a:w:Y", [SRC])
    both = make_rule("r3", SRC, [SRC, "a:w:X"])
    inherited = make_rule("r4", "a:w:Y", ["a:w:Z"])
    kw = dict(include_pending=False, now_ms=NOW_MS)
    assert mma.classify_rule(owner, SRC, **kw) == mma.KIND_OWNER
    assert mma.classify_rule(remote, SRC, **kw) == mma.KIND_REMOTE
    assert mma.classify_rule(both, SRC, **kw) == mma.KIND_BOTH
    assert mma.classify_rule(inherited, SRC, **kw) == mma.KIND_GROUP_INHERITED


def test_classify_skip_state_and_expired() -> None:
    kw = dict(include_pending=False, now_ms=NOW_MS)
    for state in (3, 6, 7):
        rule = make_rule("r", SRC, ["a:w:X"], state=state)
        assert mma.classify_rule(rule, SRC, **kw) == mma.KIND_SKIP_STATE
    expired = make_rule("r", SRC, ["a:w:X"], expires=NOW_MS - 1)
    assert mma.classify_rule(expired, SRC, **kw) == mma.KIND_SKIP_EXPIRED
    future = make_rule("r", SRC, ["a:w:X"], expires=NOW_MS + 10_000)
    assert mma.classify_rule(future, SRC, **kw) == mma.KIND_OWNER


def test_classify_pending_with_and_without_include_pending() -> None:
    pending = make_rule("r", SRC, ["a:w:X"], state=4)
    auto = make_rule("r", SRC, ["a:w:X"], state=5)
    assert mma.classify_rule(pending, SRC, include_pending=False, now_ms=NOW_MS) == mma.KIND_SKIP_PENDING
    assert mma.classify_rule(auto, SRC, include_pending=False, now_ms=NOW_MS) == mma.KIND_SKIP_PENDING
    assert mma.classify_rule(pending, SRC, include_pending=True, now_ms=NOW_MS) == mma.KIND_OWNER
    # Included pending rules are created disabled.
    assert mma.effective_state(pending) == mma.RULE_STATE_DISABLED
    assert mma.effective_state(auto) == mma.RULE_STATE_DISABLED
    enabled = make_rule("r", SRC, ["a:w:X"], state=1)
    assert mma.effective_state(enabled) == 1


def test_classify_exclusion_not_owned() -> None:
    rule = make_rule("r", "a:w:Y", ["a:w:Z"], excluded=[SRC])
    assert mma.classify_rule(rule, SRC, include_pending=False, now_ms=NOW_MS) == mma.KIND_EXCLUSION


# ---------------------------------------------------------------------------
# Rule body construction
# ---------------------------------------------------------------------------


def test_build_owner_rule_substitutes_self_reference_and_drops_src_from_excluded() -> None:
    rule = make_rule("r1", SRC, [SRC, "a:w:X", SRC, "a:w:Y"], excluded=[SRC, "a:w:E"])
    body = mma.build_owner_rule(rule, PAIR)
    assert body["localEntityId"] == DST
    assert body["remoteEntityIdsList"] == [DST, "a:w:X", "a:w:Y"]
    assert body["excludedLocalIdsList"] == ["a:w:E"]


def test_build_remote_rule_remote_is_target_only_and_block_drops_ipsec() -> None:
    allow = make_rule("r2", "a:w:Y", [SRC, "a:w:Q"], action=1, ipsec=2)
    body = mma.build_remote_rule(allow, PAIR)
    assert body["remoteEntityIdsList"] == [DST]
    assert body["localEntityId"] == "a:w:Y"
    assert body["ipSecOpt"] == 2

    block = make_rule("r3", "a:w:Y", [SRC], action=2, ipsec=2)
    block_body = mma.build_remote_rule(block, PAIR)
    assert block_body["action"] == 2
    assert "ipSecOpt" not in block_body


def test_rule_bodies_never_contain_forbidden_fields() -> None:
    rule = make_rule("r1", SRC, [SRC])
    for body in (mma.build_owner_rule(rule, PAIR), mma.build_remote_rule(rule, PAIR)):
        assert not (FORBIDDEN_BODY_KEYS & set(body))
        assert not any(key.endswith("Infos") for key in body)
        assert {"action", "localEntityId", "localProcessesList", "portsList",
                "remoteEntityIdsList", "state"} <= set(body)


def test_make_description_keeps_marker_when_trimming_original() -> None:
    long_original = "x" * 1000
    text = mma.make_description("rule-1", PAIR, long_original)
    assert len(text) == mma.DESCRIPTION_MAX_LENGTH
    assert text.startswith(f"[zn-mirror src-rule=rule-1 src={SRC} dst={DST}]")
    assert " | orig: " in text


def test_make_description_appends_original_and_handles_missing() -> None:
    text = mma.make_description("rule-2", PAIR, "block SMB")
    assert text.startswith(f"[zn-mirror src-rule=rule-2 src={SRC} dst={DST}] Mirrored from rule rule-2")
    assert text.endswith(" | orig: block SMB")
    plain = mma.make_description("rule-3", PAIR, None)
    assert " | orig:" not in plain
    marker = mma.parse_marker(plain)
    assert marker == ("rule-3", SRC, DST)


def test_rule_fingerprint_equality_and_inequality() -> None:
    a = make_rule("r1", DST, ["a:w:X", "a:w:Y"], expires=None)
    b = make_rule("r2", DST, ["a:w:Y", "a:w:X"], expires=0)
    b["portsList"] = [{"protocolType": 6, "ports": "445"}]
    assert mma.rule_fingerprint(1, a) == mma.rule_fingerprint(1, b)
    assert mma.rule_fingerprint(1, a) != mma.rule_fingerprint(2, a)
    changed = make_rule("r3", DST, ["a:w:X", "a:w:Y"])
    changed["portsList"] = [{"protocolType": 6, "ports": "3389"}]
    assert mma.rule_fingerprint(1, a) != mma.rule_fingerprint(1, changed)
    different_action = make_rule("r4", DST, ["a:w:X", "a:w:Y"], action=2)
    assert mma.rule_fingerprint(1, a) != mma.rule_fingerprint(1, different_action)


def test_dedupe_within_run_and_existing_target_rule_skipped() -> None:
    opts = default_opts()
    target = mma.TargetIndex()
    planned: set[tuple] = set()
    first = make_rule("r1", SRC, ["a:w:X"])
    second = make_rule("r2", SRC, ["a:w:X"])
    actions = mma.plan_rule_actions(first, "inbound", PAIR, opts, target, planned)
    assert [a.status for a in actions] == ["planned"]
    actions = mma.plan_rule_actions(second, "inbound", PAIR, opts, target, planned)
    assert [a.status for a in actions] == ["skipped_exists"]

    existing = mma.build_owner_rule(first, PAIR)
    target.add_rules(1, [{**existing, "id": "on-t", "description": "no marker"}])
    actions = mma.plan_rule_actions(make_rule("r9", SRC, ["a:w:X"]), "inbound", PAIR,
                                    opts, target, set())
    assert [a.status for a in actions] == ["skipped_exists"]


def test_marker_on_target_skips_create() -> None:
    opts = default_opts()
    target = mma.TargetIndex()
    target.add_rules(1, [{"description": mma.make_description("r1", PAIR, None), "action": 1}])
    actions = mma.plan_rule_actions(make_rule("r1", SRC, ["a:w:X"]), "inbound", PAIR,
                                    opts, target, set())
    assert actions[0].status == "skipped_exists"


# ---------------------------------------------------------------------------
# Classification -> action mapping
# ---------------------------------------------------------------------------


def test_both_rule_emits_owner_copy_only_unless_self_ref_both() -> None:
    rule = make_rule("rb", SRC, [SRC, "a:w:X"])
    owner_only = mma.plan_rule_actions(rule, "outbound", PAIR, default_opts(),
                                       mma.TargetIndex(), set())
    assert [a.category for a in owner_only] == ["owner_rule"]
    both = mma.plan_rule_actions(rule, "outbound", PAIR, default_opts(self_ref_both=True),
                                 mma.TargetIndex(), set())
    assert [a.category for a in both] == ["owner_rule", "outbound_remote_rule"]


def test_skip_flags_suppress_categories() -> None:
    remote = make_rule("rr", "a:w:Y", [SRC])
    actions = mma.plan_rule_actions(remote, "inbound", PAIR,
                                    default_opts(skip_inbound_remote=True),
                                    mma.TargetIndex(), set())
    assert actions == []
    owner = make_rule("ro", SRC, ["a:w:X"])
    actions = mma.plan_rule_actions(owner, "inbound", PAIR,
                                    default_opts(skip_owner_rules=True),
                                    mma.TargetIndex(), set())
    assert actions == []


def test_group_inherited_and_state_rows_are_reported_without_writes() -> None:
    inherited = make_rule("ri", "a:w:Y", ["a:w:Z"])
    actions = mma.plan_rule_actions(inherited, "inbound", PAIR, default_opts(),
                                    mma.TargetIndex(), set())
    assert actions[0].status == "skipped_group_inherited"
    assert actions[0].method == ""
    deleted = make_rule("rd", SRC, ["a:w:X"], state=3)
    actions = mma.plan_rule_actions(deleted, "outbound", PAIR, default_opts(),
                                    mma.TargetIndex(), set())
    assert actions[0].status == "skipped_state"
    excluded = make_rule("rx", "a:w:Y", ["a:w:Z"], excluded=[SRC])
    actions = mma.plan_rule_actions(excluded, "inbound", PAIR, default_opts(),
                                    mma.TargetIndex(), set())
    assert actions[0].status == "exclusion_not_mirrored"
    assert actions[0].method == ""


# ---------------------------------------------------------------------------
# Groups, pagination, pre-checks
# ---------------------------------------------------------------------------


def test_group_writability() -> None:
    assert mma.group_writable_kind("g:c:1a2b3c4d") == "custom"
    assert mma.group_writable_kind("g:t:1a2b3c4d") == "tag"
    for gid in ("g:a:1a2b3c4d", "g:s:1a2b3c4d", "g:o:1a2b3c4d", "g:x:1a2b3c4d", "junk"):
        assert mma.group_writable_kind(gid) is None


def test_minimal_groups_drops_ancestors_of_listed_groups() -> None:
    parent, child, other = "g:c:parent00", "g:c:child000", "g:t:other000"
    kept = mma.minimal_groups([parent, child, other], {child: {parent}, other: set()})
    assert kept == [child, other]
    assert mma.minimal_groups([parent, child], {}) == [parent, child]


def test_paginate_offset_requests_next_page_at_exactly_400() -> None:
    offsets: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        offset = int(request.url.params["_offset"])
        assert int(request.url.params["_limit"]) == 400
        offsets.append(offset)
        count = 400 if offset == 0 else 0
        return httpx.Response(200, json={"items": [{"id": str(i)} for i in range(count)]})

    items = run_with_client(handler, lambda c: mma.paginate_offset(c, "/x", {}, 400))
    assert len(items) == 400
    assert offsets == [0, 400]


def test_paginate_offset_stops_on_short_page() -> None:
    offsets: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        offsets.append(int(request.url.params["_offset"]))
        return httpx.Response(200, json={"items": [{"id": "1"}] * 399})

    items = run_with_client(handler, lambda c: mma.paginate_offset(c, "/x", {}, 400))
    assert len(items) == 399
    assert offsets == [0]


def test_precheck_fails_on_same_asset_inactive_target_and_ot() -> None:
    assets = {
        SRC: asset(SRC),
        DST: asset(DST, inactiveReason=2),
        "a:o:OTASSET1": asset("a:o:OTASSET1"),
    }

    def handler(request: httpx.Request) -> httpx.Response:
        asset_id = request.url.path.rsplit("/", 1)[-1]
        if asset_id not in assets:
            return httpx.Response(404, json={})
        return httpx.Response(200, json={"entity": assets[asset_id]})

    async def check(client: httpx.AsyncClient) -> list[str]:
        results = []
        results.append((await mma.precheck_pair(client, mma.AssetPair(SRC, "", SRC, "")))[0].status)
        results.append((await mma.precheck_pair(client, PAIR))[0].reason)
        ot = mma.AssetPair("a:o:OTASSET1", "", DST, "")
        results.append((await mma.precheck_pair(client, ot))[0].status)
        missing = mma.AssetPair(SRC, "", "a:w:NOPE", "")
        results.append((await mma.precheck_pair(client, missing))[0].reason)
        return results

    statuses = run_with_client(handler, check)
    assert statuses[0] == "failed"
    assert statuses[1] == "target asset is inactive"
    assert statuses[2] == "failed"
    assert "not found" in statuses[3]


# ---------------------------------------------------------------------------
# Full pair runs: dry run must make zero non-GET requests
# ---------------------------------------------------------------------------


def build_fake_backend() -> FakeZN:
    """Source with an owner rule, a remote rule, a deleted rule, an AD group and a custom group."""
    assets = {
        SRC: asset(SRC, source=3),
        DST: asset(DST),
    }
    s_inbound = [
        make_rule("rule-owner-in", SRC, ["a:w:X"]),
        make_rule("rule-remote-in", "a:w:Y", [SRC]),
        make_rule("rule-deleted", SRC, ["a:w:X"], state=3),
        make_rule("rule-inherited", "a:w:Y", ["a:w:Z"]),
    ]
    s_outbound = [make_rule("rule-owner-out", SRC, ["a:w:X"], action=2, ipsec=None)]
    rules = {
        ("inbound", SRC): s_inbound,
        ("outbound", SRC): s_outbound,
    }
    groups = {
        SRC: [{"id": "g:c:aaaa1111"}, {"id": "g:a:bbbb2222"}],
        DST: [],
    }
    return FakeZN(assets, rules, groups)


def test_dry_run_makes_only_get_requests_and_plans_expected_rows(tmp_path: Path) -> None:
    fake = build_fake_backend()
    pairs_csv = tmp_path / "pairs.csv"
    pairs_csv.write_text(
        "srcAssetId,srcAssetName,dstAssetId,dstAssetName\n"
        f"{SRC},SrcHost,{DST},DstHost\n",
        encoding="utf-8",
    )
    args = argparse.Namespace(input=str(pairs_csv), resume=None, apply=False, verbose_dry_run=False)
    out_dir = tmp_path / "outputs"

    rc = run_with_client(
        fake,
        lambda c: mma.run_forward(c, args, default_opts(), out_dir, "20260101-000000"),
    )

    assert rc == 0
    assert fake.methods, "expected some GET requests"
    assert set(fake.methods) == {"GET"}
    plan = out_dir / "manual-mirror-plan-20260101-000000.csv"
    assert plan.is_file()
    with plan.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    cat, st = mma.CATEGORY_LABELS, mma.STATUS_LABELS
    statuses = {(r["Category"], r["Source Object ID"]): r["Status"] for r in rows}
    assert statuses[(cat["precheck"], SRC)] == "Warning"  # AD source to non-AD target
    assert statuses[(cat["group"], "g:a:bbbb2222")] == st["skipped_readonly"]
    assert statuses[(cat["group"], "g:c:aaaa1111")] == "Will be added"
    assert statuses[(cat["owner_rule"], "rule-owner-in")] == st["planned"]
    assert statuses[(cat["owner_rule"], "rule-owner-out")] == st["planned"]
    assert statuses[(cat["inbound_remote_rule"], "rule-remote-in")] == st["planned"]
    assert statuses[(cat["owner_rule"], "rule-deleted")] == st["skipped_state"]
    assert statuses[(cat["inbound_remote_rule"], "rule-inherited")] == st["skipped_group_inherited"]
    planned_bodies = [r for r in rows if r["Status"] == st["planned"]
                      and r["Category"] == cat["inbound_remote_rule"]]
    assert json.loads(planned_bodies[0]["Request Body (JSON)"])["remoteEntityIdsList"] == [DST]


def test_execute_action_handles_success_conflict_and_delete() -> None:
    created_bodies: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path.endswith("/inbound"):
            created_bodies.append(json.loads(request.content))
            return httpx.Response(200, json={"item": {"id": "new-1"}})
        if request.method == "POST" and request.url.path.endswith("/outbound"):
            return httpx.Response(409, json={"error": "exists"})
        if request.method == "DELETE":
            return httpx.Response(200, json={})
        return httpx.Response(500, json={})

    body = {"action": 1, "localEntityId": DST, "remoteEntityIdsList": [DST]}
    ok = mma.Action(PAIR, "owner_rule", "r1", "create_inbound_rule", "POST",
                    "/protection/rules/inbound", body)
    conflict = mma.Action(PAIR, "owner_rule", "r2", "create_outbound_rule", "POST",
                          "/protection/rules/outbound", body)
    delete = mma.Action(PAIR, "owner_rule", "r1", "rollback", "DELETE",
                        "/protection/rules/inbound/new-1")

    async def go(client: httpx.AsyncClient) -> None:
        sem = asyncio.Semaphore(2)
        await mma.execute_action(client, sem, ok, None, {})
        await mma.execute_action(client, sem, conflict, None, {})
        await mma.execute_action(client, sem, delete, None, {})

    run_with_client(handler, go)
    assert (ok.status, ok.new_id) == ("created", "new-1")
    assert conflict.status == "skipped_exists"
    assert delete.status == "rolled_back"
    assert created_bodies[0]["localEntityId"] == DST


def test_plan_rollback_uses_direction_and_group_membership() -> None:
    rows = [
        {"srcAssetId": SRC, "srcAssetName": "s", "dstAssetId": DST, "dstAssetName": "d",
         "category": "owner_rule", "sourceObjectId": "r1", "operation": "create_outbound_rule",
         "status": "created", "newObjectId": "new-9", "reason": "", "bodyJson": ""},
        {"srcAssetId": SRC, "srcAssetName": "s", "dstAssetId": DST, "dstAssetName": "d",
         "category": "group", "sourceObjectId": "g:c:aaaa1111", "operation": "add_member",
         "status": "created", "newObjectId": "", "reason": "", "bodyJson": ""},
        {"srcAssetId": SRC, "srcAssetName": "s", "dstAssetId": DST, "dstAssetName": "d",
         "category": "owner_rule", "sourceObjectId": "r2", "operation": "create_inbound_rule",
         "status": "failed", "newObjectId": "", "reason": "x", "bodyJson": ""},
    ]
    actions = mma.plan_rollback(rows)
    assert [(a.method, a.path) for a in actions] == [
        ("DELETE", "/protection/rules/outbound/new-9"),
        ("DELETE", "/groups/custom/g:c:aaaa1111/members"),
    ]
    assert actions[1].body == {"membersId": [DST]}


# ---------------------------------------------------------------------------
# Secondary categories: shared helpers
# ---------------------------------------------------------------------------

WINDOWS_TARGET = {"id": DST, "source": 1, "operatingSystem": "Windows Server 2019"}
AD_TARGET = {"id": DST, "source": 3, "operatingSystem": "Windows Server 2019"}
LINUX_TARGET = {"id": DST, "source": 1, "operatingSystem": "Ubuntu 22.04"}
ALL_SECONDARY = dict(include_switch=True, include_external_access=True)


def secondary_opts(**overrides: Any) -> mma.RunOptions:
    """RunOptions with every secondary category enabled unless overridden."""
    return default_opts(**{**ALL_SECONDARY, **overrides})


def mfa_policy(policy_id: str, dst: str, srcs: list[str], *, excluded: list[str] | None = None,
               state: int = 1) -> dict[str, Any]:
    """An MFA policy shaped like the reactivePolicy response."""
    return {
        "id": policy_id, "description": "orig mfa", "state": state,
        "dstEntityInfo": {"id": dst, "name": dst}, "dstPort": "3389", "protocolType": 6,
        "ruleDuration": 5, "mfaMethods": [1, 3], "fallbackToLoggedOnUser": False,
        "overrideBuiltins": False, "restrictLoginToOriginatingUser": False,
        "srcEntityInfos": [{"id": s, "name": s} for s in srcs],
        "excludedSrcEntityInfos": [{"id": e, "name": e} for e in (excluded or [])],
        "srcUserInfos": [{"id": "u1", "name": "user1"}],
        "srcProcessNames": ["system"], "dstProcessNames": [], "additionalPortsList": [],
        "createdAt": 1, "updatedAt": 2, "createdBy": "x", "updatedBy": "y",
    }


def identity_policy(policy_id: str, dst: str, srcs: list[str], *, state: int = 1) -> dict[str, Any]:
    """An identity MFA policy shaped like the identityReactivePolicy response."""
    return {
        "id": policy_id, "description": "orig idmfa", "state": state,
        "dstAssetId": dst, "dstEntityInfo": {"id": dst, "name": dst},
        "srcAssetIdsList": srcs, "srcAssetInfos": [{"id": s, "name": s} for s in srcs],
        "srcUserInfos": [{"id": "u1", "name": "user1"}], "excludedSrcAssetIdsList": [],
        "excludedDstAssetIdsList": [], "mfaMethodsList": [2], "ruleDuration": 2,
        "identityProtectionCategoryList": [1, 5], "overrideBuiltins": False,
        "fallbackToSingleLoggedOnUser": True, "restrictLoginToOriginatingUser": False,
        "createdAt": 1, "updatedAt": 2,
    }


def rpc_rule(rule_id: str, local: str, remote: list[str], *, action: int = 1,
             excluded: list[str] | None = None) -> dict[str, Any]:
    """An RPC rule shaped like the rpcRule response."""
    return {
        "id": rule_id, "action": action, "state": 1, "localAssetId": local,
        "remoteAssetIdsList": remote, "excludedAssetIdsList": excluded or [],
        "interfaceUuidsList": ["rpcAnyInterface"], "opNumbersList": [], "protocolsList": [1],
        "userIdsList": [], "description": "orig rpc", "createdAt": 1,
    }


def switch_rule(rule_id: str, local: str, remote: list[str], *, direction_path: str = "inbound",
                **extra: Any) -> dict[str, Any]:
    """A switch rule shaped like the switchRule response (remoteEntitiesIdList)."""
    rule: dict[str, Any] = {
        "id": rule_id, "action": 1, "state": 1, "localEntityId": local,
        "remoteEntitiesIdList": remote, "localProcessesList": ["*"], "servicesList": [],
        "excludedLocalIdsList": [], "protocolsList": [{"localPorts": "*", "protocolType": 6,
                                                       "remotePorts": "445"}],
        "description": "orig switch", "srcUserInfos": [], "expiresAt": None,
        "createdAt": 1, "direction": 1 if direction_path == "inbound" else 2,
    }
    rule.update(extra)
    return rule


def external_policy(policy_id: str, dst: str) -> dict[str, Any]:
    """An external access policy shaped like the externalAccessPolicy response."""
    return {
        "id": policy_id, "name": "web-access", "description": "orig ext", "state": 1,
        "dstAssetId": dst, "dstPortsList": [{"protocolType": 6, "ports": "443"}],
        "dstProcessNamesList": ["*"], "srcUserIdsList": ["u1"], "ruleDuration": 5,
        "url": "https://example.test", "createdAt": 1,
    }


def connect_config(config_id: str, *, allowed: list[str] = (), excluded: list[str] = (),
                   destinations: list[str] = ()) -> dict[str, Any]:
    """A Connect user access config shaped like the connectUserAccessConfig response."""
    return {
        "id": config_id, "name": f"cfg-{config_id}", "description": "vpn", "allowedRegions": [],
        "connectivityStateAfterReboot": 1, "forceSsoAuthentication": False, "sessionTtlHours": 8,
        "allowedAssetIds": [{"id": a, "name": a} for a in allowed],
        "excludedAssetIds": [{"id": e, "name": e} for e in excluded],
        "allowedDestinations": [{"id": d, "name": d} for d in destinations],
        "allowedAssetSources": [{"id": "src1", "name": "src1"}],
        "allowedUserIds": [{"id": "u1", "name": "user1"}], "excludedUserIds": [],
        "createdAt": 1,
    }


# ---------------------------------------------------------------------------
# MFA policies
# ---------------------------------------------------------------------------


def test_mfa_bodies_owner_and_remote_reduce_lists_and_drop_forbidden_fields() -> None:
    owner = mfa_policy("pol-1", SRC, [SRC, "a:w:X"], excluded=[SRC, "a:w:E"])
    body = mma.build_mfa_body(owner, PAIR, owner=True, state=1)
    assert body["dstEntityInfo"] == {"id": DST}
    assert body["srcEntityInfos"] == [{"id": DST}, {"id": "a:w:X"}]
    assert body["excludedSrcEntityInfos"] == [{"id": "a:w:E"}]
    assert body["srcUserInfos"] == [{"id": "u1"}]
    assert not (FORBIDDEN_BODY_KEYS & set(body))
    assert not any(key in body for key in ("createdAt", "updatedAt", "createdBy"))

    remote = mfa_policy("pol-2", "a:w:D", [SRC, "a:w:X"])
    remote_body = mma.build_mfa_body(remote, PAIR, owner=False, state=2)
    assert remote_body["dstEntityInfo"] == {"id": "a:w:D"}
    assert remote_body["srcEntityInfos"] == [{"id": DST}]
    assert remote_body["state"] == 2


def test_mfa_fingerprint_matches_existing_target_policy() -> None:
    body = mma.build_mfa_body(mfa_policy("pol-1", SRC, [SRC]), PAIR, owner=True, state=1)
    existing = {**body, "id": "t-1", "description": None, "createdAt": 9}
    assert mma.mfa_fingerprint(1, existing) == mma.mfa_fingerprint(1, body)
    assert mma.mfa_fingerprint(2, body) != mma.mfa_fingerprint(1, body)


def test_mfa_collector_plans_copies_skips_existing_and_executes_post() -> None:
    owner = mfa_policy("pol-owner", SRC, [SRC, "a:w:X"])
    remote = mfa_policy("pol-remote", "a:w:D", [SRC])
    owner_body = mma.build_mfa_body(owner, PAIR, owner=True, state=1)
    target_existing = {**owner_body, "id": "t-1", "description": None}
    inbound_by_entity = {
        SRC: [owner, remote],
        DST: [target_existing],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(200, json={"item": {"id": "new-mfa"}})
        if route_path(request) == "/protection/reactive-policies/inbound":
            return json_ok(inbound_by_entity.get(request.url.params["_entityId"], []))
        if route_path(request) == "/protection/reactive-policies/outbound":
            return json_ok([])
        return httpx.Response(404, json={})

    recorder = Recorder(handler)

    async def go(client: httpx.AsyncClient) -> list[mma.Action]:
        actions = await mma.collect_mfa_actions(client, PAIR, secondary_opts(), set())
        sem = asyncio.Semaphore(2)
        writes = [a for a in actions if a.status == "planned"]
        await asyncio.gather(*(mma.execute_action(client, sem, a, None, {}) for a in writes))
        return actions

    actions = run_with_client(recorder, go)
    assert recorder.methods == {"GET", "POST"}
    statuses = {a.source_object_id: a.status for a in actions}
    assert statuses["pol-owner"] == "skipped_exists"
    assert statuses["pol-remote"] == "created"
    posted = [r for r in recorder.requests if r.method == "POST"]
    assert len(posted) == 1
    assert posted[0].url.path.endswith("/protection/reactive-policies/inbound")
    assert json.loads(posted[0].content)["dstEntityInfo"] == {"id": "a:w:D"}


def test_mfa_excluded_only_and_pending_states_are_reported() -> None:
    excluded_only = mfa_policy("pol-x", "a:w:Y", ["a:w:Z"], excluded=[SRC])
    deleted = mfa_policy("pol-d", SRC, ["a:w:X"], state=3)
    actions = mma.plan_mfa_policy(excluded_only, "inbound", PAIR, secondary_opts(),
                                  mma.ObjectIndex(), set())
    assert [(a.status, a.method) for a in actions] == [("exclusion_not_mirrored", "")]
    actions = mma.plan_mfa_policy(deleted, "inbound", PAIR, secondary_opts(),
                                  mma.ObjectIndex(), set())
    assert [(a.status, a.method) for a in actions] == [("skipped_state", "")]


# ---------------------------------------------------------------------------
# Identity rules and identity MFA (AD / Azure AD targets)
# ---------------------------------------------------------------------------


def test_identity_rule_body_and_cursor_pagination_follows_next_cursor() -> None:
    rule = {"id": "idr-1", "action": 1, "state": 1, "assetId": SRC,
            "identityProtectionCategoryList": [1, 5], "userIdsList": ["u1"],
            "excludedAssetIdsList": [SRC, "a:w:E"], "description": "idr", "expiresAt": None}
    body = mma.build_identity_rule_body(rule, PAIR, state=1)
    assert body["assetId"] == DST
    assert body["excludedAssetIdsList"] == ["a:w:E"]
    assert body["identityProtectionCategoryList"] == [1, 5]
    assert "expiresAt" not in body
    assert mma.identity_rule_fingerprint({**body, "id": "t-1"}) == mma.identity_rule_fingerprint(body)

    cursors: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        cursors.append(request.url.params.get("_cursor"))
        if "_cursor" not in request.url.params:
            return json_ok([rule], nextCursor=1700000000000)
        return json_ok([{**rule, "id": "idr-2"}])

    items = run_with_client(Recorder(handler), lambda c: mma.paginate_cursor(c, "/assets/x/protection/identity-rules", {}))
    assert [i["id"] for i in items] == ["idr-1", "idr-2"]
    assert cursors == [None, "1700000000000"]


def test_identity_gate_skips_non_ad_target_with_single_row_and_makes_no_identity_calls() -> None:
    recorder = Recorder(lambda request: json_ok([]))
    opts = secondary_opts(skip_mfa=True, skip_rpc=True, skip_connect=True)

    async def go(client: httpx.AsyncClient) -> list[mma.Action]:
        return await mma.collect_secondary_actions(client, PAIR, opts, set(), WINDOWS_TARGET)

    actions = run_with_client(recorder, go)
    assert [(a.category, a.status) for a in actions] == [("identity_rule", "incompatible_target")]
    assert not any("identity" in route_path(r) for r in recorder.requests)


def test_identity_gate_allows_azure_ad_target() -> None:
    recorder = Recorder(lambda request: json_ok([]))
    aad_target = {"id": DST, "source": 9, "operatingSystem": "Windows 11"}
    opts = secondary_opts(skip_mfa=True, skip_rpc=True, skip_connect=True)
    actions = run_with_client(
        recorder,
        lambda c: mma.collect_secondary_actions(c, PAIR, opts, set(), aad_target),
    )
    assert actions == []
    assert any("identity-rules" in route_path(r) for r in recorder.requests)


def test_identity_mfa_body_owner_and_remote_copies() -> None:
    owner = identity_policy("idm-1", SRC, [SRC, "a:w:X"])
    body = mma.build_identity_mfa_body(owner, PAIR, owner=True, state=1)
    assert body["dstAssetId"] == DST
    assert body["srcAssetIdsList"] == [DST, "a:w:X"]
    assert body["srcUserIdsList"] == ["u1"]
    assert body["mfaMethodsList"] == [2]
    assert "srcUserInfos" not in body

    remote = identity_policy("idm-2", "a:w:D", [SRC])
    remote_body = mma.build_identity_mfa_body(remote, PAIR, owner=False, state=1)
    assert remote_body["dstAssetId"] == "a:w:D"
    assert remote_body["srcAssetIdsList"] == [DST]
    existing = {**body, "id": "t-9", "description": None}
    assert mma.identity_mfa_fingerprint(existing) == mma.identity_mfa_fingerprint(body)


def test_identity_mfa_failure_is_isolated_from_other_categories() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "identity/reactive-policies" in route_path(request):
            return httpx.Response(400, json={"error": "bad request"})
        return json_ok([])

    opts = secondary_opts(skip_mfa=True, skip_connect=True)
    actions = run_with_client(
        Recorder(handler),
        lambda c: mma.collect_secondary_actions(c, PAIR, opts, set(), AD_TARGET),
    )
    failed = {a.category for a in actions if a.status == "failed"}
    assert failed == {"identity_mfa_policy"}
    assert not any(a.category == "identity_rule" and a.status == "failed" for a in actions)


# ---------------------------------------------------------------------------
# RPC rules (Windows targets)
# ---------------------------------------------------------------------------


def test_rpc_bodies_owner_and_remote_copies_carry_marker_description() -> None:
    owner = rpc_rule("rpc-1", SRC, [SRC, "a:w:X"], excluded=[SRC])
    body = mma.build_rpc_body(owner, PAIR, owner=True, state=1)
    assert body["localAssetId"] == DST
    assert body["remoteAssetIdsList"] == [DST, "a:w:X"]
    assert body["excludedAssetIdsList"] == []
    assert body["description"].startswith(f"[zn-mirror src-rule=rpc-1 src={SRC} dst={DST}]")
    for key in ("action", "description", "excludedAssetIdsList", "interfaceUuidsList", "localAssetId",
                "opNumbersList", "protocolsList", "remoteAssetIdsList", "state", "userIdsList"):
        assert key in body

    remote = rpc_rule("rpc-2", "a:w:Y", [SRC])
    remote_body = mma.build_rpc_body(remote, PAIR, owner=False, state=1)
    assert remote_body["localAssetId"] == "a:w:Y"
    assert remote_body["remoteAssetIdsList"] == [DST]


def test_rpc_gate_and_collector_copy_owner_and_remote_rules() -> None:
    assert mma.is_windows(WINDOWS_TARGET)
    assert not mma.is_windows(LINUX_TARGET)
    rules_by_asset = {
        SRC: [rpc_rule("rpc-own", SRC, ["a:w:X"]), rpc_rule("rpc-rem", "a:w:Y", [SRC])],
        DST: [],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        path = route_path(request)
        if path.startswith("/assets/") and path.endswith("/protection/rpc-rules"):
            asset_id = path.split("/")[2]
            return json_ok(rules_by_asset.get(asset_id, []))
        return json_ok([])

    opts = secondary_opts(skip_mfa=True, skip_identity=True, skip_connect=True)
    actions = run_with_client(
        Recorder(handler),
        lambda c: mma.collect_secondary_actions(c, PAIR, opts, set(), WINDOWS_TARGET),
    )
    by_id = {a.source_object_id: a for a in actions if a.category == "rpc_rule"}
    assert by_id["rpc-own"].status == "planned" and by_id["rpc-own"].body["localAssetId"] == DST
    assert by_id["rpc-rem"].status == "planned" and by_id["rpc-rem"].body["remoteAssetIdsList"] == [DST]
    assert by_id["rpc-rem"].path == "/protection/rpc-rules"

    linux_actions = run_with_client(
        Recorder(handler),
        lambda c: mma.collect_secondary_actions(c, PAIR, opts, set(), LINUX_TARGET),
    )
    assert [(a.category, a.status) for a in linux_actions] == [("rpc_rule", "incompatible_target")]


# ---------------------------------------------------------------------------
# Switch rules (opt-in)
# ---------------------------------------------------------------------------


def test_switch_body_uses_required_remote_field_and_disables_mirror_rules() -> None:
    rule = switch_rule("sw-1", SRC, [SRC, "a:w:X"])
    body = mma.build_switch_body(rule, "inbound", PAIR, owner=True, state=1)
    assert body["localEntityId"] == DST
    assert body["remoteEntityIdsList"] == [DST, "a:w:X"]
    assert "remoteEntitiesIdList" not in body
    assert body["shouldBuildMirrorRules"] is False
    assert body["direction"] == 1
    assert body["protocolsList"] == rule["protocolsList"]

    remote = switch_rule("sw-2", "a:w:Y", [SRC])
    remote_body = mma.build_switch_body(remote, "outbound", PAIR, owner=False, state=1)
    assert remote_body["localEntityId"] == "a:w:Y"
    assert remote_body["remoteEntityIdsList"] == [DST]
    assert remote_body["direction"] == 2


def test_switch_rules_off_by_default_and_derived_rules_skipped() -> None:
    recorder = Recorder(lambda request: json_ok([]))
    opts = default_opts(skip_mfa=True, skip_identity=True, skip_rpc=True, skip_connect=True)
    run_with_client(recorder, lambda c: mma.collect_secondary_actions(c, PAIR, opts, set(), WINDOWS_TARGET))
    assert not any("switch-rules" in route_path(r) for r in recorder.requests)

    rules = [
        switch_rule("sw-owner", SRC, ["a:w:X"]),
        switch_rule("sw-remote", "a:w:Y", [SRC]),
        switch_rule("sw-derived", SRC, ["a:w:X"], mirrorNetworkRuleId="11111111-2222-3333-4444-555555555555"),
        switch_rule("sw-unrelated", "a:w:P", ["a:w:Q"]),
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        if route_path(request) == "/protection/switch-rules/inbound":
            return json_ok(rules)
        return json_ok([])

    opts = secondary_opts(skip_mfa=True, skip_identity=True, skip_rpc=True, skip_connect=True)
    actions = run_with_client(Recorder(handler), lambda c: mma.collect_switch_actions(c, PAIR, opts, set()))
    statuses = {a.source_object_id: a.status for a in actions}
    assert statuses == {"sw-owner": "planned", "sw-remote": "planned", "sw-derived": "skipped_derived"}
    assert all(a.path == "/protection/switch-rules/inbound" for a in actions if a.method)


# ---------------------------------------------------------------------------
# External access policies (opt-in)
# ---------------------------------------------------------------------------


def test_external_access_body_is_recreated_for_target_and_skips_existing() -> None:
    policy = external_policy("ext-1", SRC)
    body = mma.build_external_access_body(policy, PAIR, state=1)
    assert body["dstAssetId"] == DST
    assert body["srcUserIdsList"] == ["u1"]
    assert body["url"] == "https://example.test"
    assert body["description"].startswith(f"[zn-mirror src-rule=ext-1 src={SRC} dst={DST}]")

    existing = {**body, "id": "t-ext", "description": None}
    assert mma.external_access_fingerprint(existing) == mma.external_access_fingerprint(body)

    def handler(request: httpx.Request) -> httpx.Response:
        path = route_path(request)
        if path == f"/assets/{SRC}/protection/external-access-policies":
            return json_ok([policy, external_policy("ext-other", "a:w:Z")])
        if path == f"/assets/{DST}/protection/external-access-policies":
            return json_ok([existing])
        return json_ok([])

    actions = run_with_client(
        Recorder(handler),
        lambda c: mma.collect_external_access_actions(c, PAIR, secondary_opts(), set()),
    )
    assert [(a.source_object_id, a.status) for a in actions] == [("ext-1", "skipped_exists")]


def test_external_access_planned_post_targets_asset_scoped_path() -> None:
    policy = external_policy("ext-2", SRC)

    def handler(request: httpx.Request) -> httpx.Response:
        path = route_path(request)
        if path == f"/assets/{SRC}/protection/external-access-policies":
            return json_ok([policy])
        return json_ok([])

    actions = run_with_client(
        Recorder(handler),
        lambda c: mma.collect_external_access_actions(c, PAIR, secondary_opts(), set()),
    )
    assert actions[0].status == "planned"
    assert actions[0].path == f"/assets/{DST}/protection/external-access-policies"


# ---------------------------------------------------------------------------
# Connect (VPN) roles: body builder, collector, serial re-read executor
# ---------------------------------------------------------------------------


def test_connect_body_adds_target_next_to_source_and_maps_field_names() -> None:
    config = connect_config("v:abc12345", allowed=["x", SRC], excluded=[SRC], destinations=["d1"])
    body = mma.build_connect_body(config, PAIR)
    assert body is not None
    lae = body["loginAuthorizedEntities"]
    assert lae["allowedAssetIdsList"] == ["x", SRC, DST]
    assert lae["excludedAssetIdsList"] == [SRC, DST]
    assert lae["allowedUsersIdsList"] == ["u1"]
    assert lae["allowedAssetsSourcesList"] == ["src1"]
    assert body["dstEntityIdsList"] == ["d1"]
    assert body["name"] == "cfg-v:abc12345"
    assert body["sessionTtlHours"] == 8

    already = connect_config("v:abc12345", allowed=[SRC, DST])
    assert mma.build_connect_body(already, PAIR) is None
    unrelated = connect_config("v:other000", allowed=["x"])
    assert mma.build_connect_body(unrelated, PAIR) is None


def test_connect_collector_plans_put_or_skips_when_target_present() -> None:
    configs = [
        connect_config("v:needs000", allowed=[SRC]),
        connect_config("v:haves000", destinations=[SRC, DST]),
        connect_config("v:none0000", allowed=["x"]),
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        if route_path(request) == "/settings/connect/user-access-config":
            return json_ok(configs)
        return json_ok([])

    actions = run_with_client(Recorder(handler),
                              lambda c: mma.collect_connect_actions(c, PAIR, secondary_opts(), set()))
    by_id = {a.source_object_id: a for a in actions}
    assert set(by_id) == {"v:needs000", "v:haves000"}
    assert by_id["v:needs000"].method == "PUT"
    assert by_id["v:needs000"].path == "/settings/connect/user-access-config/v:needs000"
    assert by_id["v:haves000"].status == "skipped_exists"


def test_connect_updates_are_serial_and_rebuilt_from_fresh_copy() -> None:
    state = {"v:shared00": connect_config("v:shared00", allowed=[SRC, "a:w:S2"])}
    pair2 = mma.AssetPair(src_id="a:w:S2", src_name="s2", dst_id="a:w:T2", dst_name="t2")
    put_bodies: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and route_path(request) == "/settings/connect/user-access-config":
            return json_ok(list(state.values()))
        if request.method == "PUT":
            body = json.loads(request.content)
            put_bodies.append(body)
            cid = route_path(request).rsplit("/", 1)[-1]
            lae = body["loginAuthorizedEntities"]
            state[cid] = connect_config(cid, allowed=lae["allowedAssetIdsList"])
            return httpx.Response(200, json={})
        return httpx.Response(405, json={})

    recorder = Recorder(handler)

    async def go(client: httpx.AsyncClient) -> list[mma.Action]:
        opts = secondary_opts()
        planned: set[tuple] = set()
        actions = []
        for pair in (PAIR, pair2):
            actions += await mma.collect_connect_actions(client, pair, opts, planned)
        await mma.execute_actions(client, actions, 5, None, {})
        return actions

    actions = run_with_client(recorder, go)
    assert [a.status for a in actions] == ["updated", "updated"]
    assert len(put_bodies) == 2
    assert put_bodies[0]["loginAuthorizedEntities"]["allowedAssetIdsList"] == [SRC, DST, "a:w:S2"]
    assert put_bodies[1]["loginAuthorizedEntities"]["allowedAssetIdsList"] == [SRC, DST, "a:w:S2", "a:w:T2"]
    assert state["v:shared00"]["allowedAssetIds"][-1]["id"] == "a:w:T2"


def test_connect_executor_skips_when_target_added_concurrently() -> None:
    state = {"v:race0000": connect_config("v:race0000", allowed=[SRC])}
    puts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return json_ok(list(state.values()))
        puts.append(request.method)
        return httpx.Response(200, json={})

    recorder = Recorder(handler)

    async def go(client: httpx.AsyncClient) -> list[mma.Action]:
        actions = await mma.collect_connect_actions(client, PAIR, secondary_opts(), set())
        # Someone else adds the target between the plan and the write.
        state["v:race0000"] = connect_config("v:race0000", allowed=[SRC, DST])
        await mma.execute_actions(client, actions, 5, None, {})
        return actions

    actions = run_with_client(recorder, go)
    assert actions[0].status == "skipped_exists"
    assert puts == []


# ---------------------------------------------------------------------------
# Rollback, dry run and the full secondary pipeline
# ---------------------------------------------------------------------------


def test_plan_rollback_covers_secondary_categories() -> None:
    base = {"srcAssetId": SRC, "srcAssetName": "s", "dstAssetId": DST, "dstAssetName": "d",
            "reason": "", "bodyJson": "", "status": "created"}
    rows = [
        {**base, "category": "mfa_policy", "sourceObjectId": "p1",
         "operation": "create_inbound_mfa_policy", "newObjectId": "m-1"},
        {**base, "category": "switch_rule", "sourceObjectId": "s1",
         "operation": "create_outbound_switch_rule", "newObjectId": "w-1"},
        {**base, "category": "identity_rule", "sourceObjectId": "i1",
         "operation": "create_identity_rule", "newObjectId": "i-9"},
        {**base, "category": "external_access_policy", "sourceObjectId": "e1",
         "operation": "create_external_access_policy", "newObjectId": "e-1"},
        {**base, "category": "connect_role", "sourceObjectId": "v:x",
         "operation": mma.CONNECT_OPERATION, "status": "updated", "newObjectId": ""},
    ]
    actions = mma.plan_rollback(rows)
    assert [(a.method, a.path) for a in actions if a.method] == [
        ("DELETE", "/protection/reactive-policies/inbound/m-1"),
        ("DELETE", "/protection/switch-rules/outbound/w-1"),
        ("DELETE", "/protection/identity-rules/i-9"),
        ("DELETE", "/protection/external-access-policies/e-1"),
    ]
    unsupported = [a for a in actions if a.status == "rollback_unsupported"]
    assert len(unsupported) == 1 and unsupported[0].category == "connect_role"


def test_secondary_pipeline_is_read_only_in_dry_run() -> None:
    config = connect_config("v:dry00000", allowed=[SRC])
    handled: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        handled.append(request.method)
        path = route_path(request)
        if path == "/protection/reactive-policies/inbound":
            return json_ok([mfa_policy("p-1", SRC, ["a:w:X"])])
        if path == "/settings/connect/user-access-config":
            return json_ok([config])
        return json_ok([])

    recorder = Recorder(handler)
    opts = secondary_opts()
    actions = run_with_client(recorder, lambda c: mma.collect_secondary_actions(c, PAIR, opts, set(), AD_TARGET))
    assert recorder.methods == {"GET"}
    assert {a.method for a in actions if a.status == "planned"} <= {"POST", "PUT"}
    assert any(a.category == "connect_role" and a.method == "PUT" for a in actions)
    assert not any(a.status == "failed" for a in actions)


def test_target_inactive_treats_reason_3_none_as_active() -> None:
    """inactiveReason 3 is the enum value for "None" and is returned for active assets."""
    assert mma.target_inactive({"inactiveReason": 3}) is False
    assert mma.target_inactive({"inactiveReason": None}) is False
    assert mma.target_inactive({}) is False
    for reason in (1, 2, 4, 5, 6):
        assert mma.target_inactive({"inactiveReason": reason}) is True
    assert mma.target_inactive({"inactiveReason": 3, "inactiveSince": 1700000000000}) is True


def test_run_category_404_is_skipped_unavailable_not_failed() -> None:
    """A 404 from a category's list endpoint means the feature is absent, not an error."""
    request = httpx.Request("GET", "https://zn.test/api/v1/settings/connect/user-access-config")

    async def collector() -> list[Any]:
        raise httpx.HTTPStatusError("nf", request=request, response=httpx.Response(404, request=request))

    actions = asyncio.run(mma._run_category("connect_role", PAIR, collector))
    assert [a.status for a in actions] == ["skipped_unavailable"]

    async def forbidden() -> list[Any]:
        raise httpx.HTTPStatusError("fb", request=request, response=httpx.Response(403, request=request))

    actions = asyncio.run(mma._run_category("connect_role", PAIR, forbidden))
    assert [a.status for a in actions] == ["failed"]


# ---------------------------------------------------------------------------
# Dated output directory, host labels, CLI flags
# ---------------------------------------------------------------------------

TS = "20260101-120000"


def test_dated_output_dir_uses_run_date() -> None:
    assert mma.dated_output_dir("outputs", datetime(2026, 11, 4, 9, 30, 15)) == Path("outputs/2026-11-04")


def test_parse_args_verbose_dry_run_spellings_and_verbose_flag(capsys: pytest.CaptureFixture) -> None:
    base = ["--input", "pairs.csv"]
    assert mma.parse_args(base + ["--verbose-dry-run"]).verbose_dry_run is True
    assert mma.parse_args(base + ["--verboseDryRun"]).verbose_dry_run is True
    assert mma.parse_args(base).verbose_dry_run is False
    args = mma.parse_args(base + ["-v"])
    assert args.verbose is True and args.verbose_dry_run is False
    assert mma.parse_args(base + ["--verbose"]).verbose is True
    with pytest.raises(SystemExit):
        mma.parse_args(["--help"])
    help_text = capsys.readouterr().out
    assert "--verbose-dry-run" in help_text and "--verboseDryRun" in help_text


def test_host_label_shortens_fqdn_and_sanitizes() -> None:
    assert mma.host_label("server01.corp.example.com") == "server01"
    assert mma.host_label("My Host!") == "My_Host_"
    assert mma.host_label("a/b:c-d_e") == "a_b_c-d_e"
    assert mma.host_label("") == "unknown"
    assert mma.host_label(".corp") == "unknown"


def test_pair_dir_names_suffixes_only_colliding_pairs() -> None:
    p1 = mma.AssetPair("a:w:SRC00001", "web.a", "a:w:DST00001", "db.x")
    p2 = mma.AssetPair("a:w:SRC00002", "web.b", "a:w:DST00002", "db.x")
    p3 = mma.AssetPair("a:w:SRC00003", "other.z", "a:w:DST00003", "db.x")
    names = mma.pair_dir_names([p1, p2, p3])
    assert names[(p1.src_id, p1.dst_id)] == "web_to_db-DST00001"
    assert names[(p2.src_id, p2.dst_id)] == "web_to_db-DST00002"
    assert names[(p3.src_id, p3.dst_id)] == "other_to_db"


def test_pair_dir_names_adds_source_suffix_when_dst_suffix_still_collides() -> None:
    p1 = mma.AssetPair("a:w:SRC00001", "web.a", "a:w:DST00001", "db")
    p2 = mma.AssetPair("a:w:SRC00002", "web.b", "a:w:DST00001", "db")
    names = mma.pair_dir_names([p1, p2])
    assert names[(p1.src_id, p1.dst_id)] == "web_to_db-DST00001-SRC00001"
    assert names[(p2.src_id, p2.dst_id)] == "web_to_db-DST00001-SRC00002"


def test_format_ports_and_rule_meta_tolerate_missing_fields() -> None:
    ports = [{"protocolType": 6, "ports": "22"}, {"protocolType": 17, "ports": "53"},
             {"protocolType": 99, "ports": "1"}]
    assert mma._format_ports(ports) == "tcp/22,udp/53,99:1"
    meta = mma.rule_meta({"id": "x", "localEntityId": SRC, "remoteEntityIdsList": None,
                          "portsList": None, "localEntityInfos": None}, "inbound", PAIR)
    assert meta["copyType"] == "owner"
    assert meta["localEntityName"] == SRC
    assert meta["ports"] == ""
    assert meta["originalRemoteIds"] == []


def test_group_rows_carry_meta_and_readable_readonly_reason() -> None:
    fake = FakeZN({}, {}, {SRC: [
        {"id": "g:c:aaaa1111", "name": "Web"},
        {"id": "g:a:bbbb2222", "name": "AD"},
        {"id": "g:s:cccc3333", "name": "Sys"},
    ], DST: []})
    actions = run_with_client(fake, lambda c: mma.collect_group_actions(c, PAIR))
    by_id = {a.source_object_id: a for a in actions}
    assert by_id["g:a:bbbb2222"].status == "skipped_readonly"
    assert by_id["g:a:bbbb2222"].reason == "group type is read-only (AD)"
    assert by_id["g:s:cccc3333"].reason == "group type is read-only (system)"
    assert by_id["g:c:aaaa1111"].meta == {"groupName": "Web", "groupType": "custom"}
    assert by_id["g:c:aaaa1111"].status == "planned"
    assert mma.group_type_word("g:o:1") == "OT"
    assert mma.group_type_word("g:t:1") == "tag"
    assert mma.group_type_word("junk") == "unknown"


# ---------------------------------------------------------------------------
# Verbose dry-run reports
# ---------------------------------------------------------------------------

VERBOSE_RULE_STEMS = ("inbound-allow", "inbound-block", "outbound-allow", "outbound-block")
VERBOSE_STEMS = (*VERBOSE_RULE_STEMS, "groups-added", "groups-not-added")


def rule_header(stem: str) -> list[str]:
    """Expected human-readable header of a verbose rule file, chosen by its direction."""
    return [label for _key, label in mma.rule_columns(stem.split("-", 1)[0])]


def read_rows(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    """Return (header, rows) of a CSV written by the tool."""
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        return list(reader.fieldnames or []), rows


def test_write_verbose_reports_routes_rules_and_groups(tmp_path: Path) -> None:
    opts = default_opts()
    target = mma.TargetIndex()
    planned: set[tuple] = set()
    rules = [
        ("inbound", make_rule("in-allow-owner", SRC, ["a:w:X", "a:w:Y"])),
        ("inbound", make_rule("in-allow-inherited", "a:w:Y", ["a:w:Z"])),
        ("inbound", make_rule("in-allow-excluded", "a:w:Y", ["a:w:Z"], excluded=[SRC])),
        ("inbound", make_rule("in-block-remote", "a:w:Y", [SRC], action=2)),
        ("outbound", make_rule("out-allow-expired", SRC, ["a:w:X"], expires=NOW_MS - 1)),
        ("outbound", make_rule("out-block-owner", SRC, ["a:w:X"], action=2, ipsec=None)),
    ]
    actions: list[mma.Action] = []
    for direction, rule in rules:
        actions += mma.plan_rule_actions(rule, direction, PAIR, opts, target, planned)
    actions.append(mma.Action(PAIR, "owner_rule", "nometa", "create_inbound_rule", "POST", "/x"))
    actions.append(mma.Action(
        PAIR, "group", "g:c:aaaa1111", "add_member", method="PUT",
        path="/groups/custom/g:c:aaaa1111/members", meta={"groupName": "Web", "groupType": "custom"},
    ))
    actions.append(mma.Action(
        PAIR, "group", "g:a:bbbb2222", "skip", status="skipped_readonly",
        reason="group type is read-only (AD)", meta={"groupName": "AD", "groupType": "AD"},
    ))
    actions.append(mma.Action(
        PAIR, "group", "g:t:cccc3333", "skip", status="skipped_exists",
        reason="target is already a member", meta={"groupName": "T", "groupType": "tag"},
    ))
    actions.append(mma.Action(
        PAIR, "group", "g:c:dddd4444", "skip", status="skipped_redundant",
        reason="a more specific listed group already implies membership",
        meta={"groupName": "R", "groupType": "custom"},
    ))
    actions.append(mma.Action(PAIR, "precheck", SRC, "validate", status="ok"))
    lonely = mma.AssetPair("a:w:OTHER001", "lonely", "a:w:OTHER002", "dst2")

    written = mma.write_verbose_reports(actions, [PAIR, lonely], tmp_path, TS)

    assert len(written) == 12
    folder = tmp_path / "SrcHost_to_DstHost"
    lonely_folder = tmp_path / "lonely_to_dst2"
    for stem in VERBOSE_STEMS:
        assert (folder / f"{stem}-{TS}.csv").is_file()
        assert (lonely_folder / f"{stem}-{TS}.csv").is_file()

    def ids(stem: str) -> dict[str, dict[str, str]]:
        _header, rows = read_rows(folder / f"{stem}-{TS}.csv")
        return {r.get("Source Rule ID") or r.get("Group ID"): r for r in rows}

    st = mma.STATUS_LABELS
    inbound_allow = ids("inbound-allow")
    assert set(inbound_allow) == {"in-allow-owner", "in-allow-inherited", "in-allow-excluded"}
    assert inbound_allow["in-allow-owner"]["Status"] == st["planned"]
    assert inbound_allow["in-allow-owner"]["Copy Type"] == mma.copy_type_label("owner", "inbound")
    assert inbound_allow["in-allow-owner"]["Original Source Asset IDs"] == "a:w:X; a:w:Y"
    assert inbound_allow["in-allow-owner"]["Ports"] == "tcp/445"
    assert inbound_allow["in-allow-inherited"]["Status"] == st["skipped_group_inherited"]
    assert inbound_allow["in-allow-inherited"]["Reason"] == mma.SKIP_REASON[mma.KIND_GROUP_INHERITED]
    assert inbound_allow["in-allow-excluded"]["Status"] == st["exclusion_not_mirrored"]

    inbound_block = ids("inbound-block")
    assert set(inbound_block) == {"in-block-remote"}
    assert inbound_block["in-block-remote"]["Copy Type"] == mma.copy_type_label("remote", "inbound")
    assert inbound_block["in-block-remote"]["New Source Asset IDs"] == DST
    assert inbound_block["in-block-remote"]["New Source Asset Names"] == "DstHost"
    # In an inbound rule the local asset is the destination and the rule owner stays put.
    assert inbound_block["in-block-remote"]["Original Destination Asset ID (rule owner)"] == "a:w:Y"

    outbound_allow = ids("outbound-allow")
    assert set(outbound_allow) == {"out-allow-expired"}
    assert outbound_allow["out-allow-expired"]["Status"] == st["skipped_expired"]
    assert outbound_allow["out-allow-expired"]["Reason"] == mma.SKIP_REASON[mma.KIND_SKIP_EXPIRED]
    assert outbound_allow["out-allow-expired"]["Expires"] != ""
    assert outbound_allow["out-allow-expired"]["Expires"] != "Never"

    outbound_block = ids("outbound-block")
    assert set(outbound_block) == {"out-block-owner"}
    assert outbound_block["out-block-owner"]["Status"] == st["planned"]
    assert outbound_block["out-block-owner"]["Original Source Asset ID (rule owner)"] == SRC
    assert outbound_block["out-block-owner"]["Original Destination Asset IDs"] == "a:w:X"

    added = ids("groups-added")
    assert set(added) == {"g:c:aaaa1111"}
    assert added["g:c:aaaa1111"]["HTTP Method"] == "PUT"
    assert added["g:c:aaaa1111"]["Group Name"] == "Web"

    not_added = ids("groups-not-added")
    assert {k: v["Status"] for k, v in not_added.items()} == {
        "g:a:bbbb2222": st["skipped_readonly"],
        "g:t:cccc3333": st["skipped_exists"],
        "g:c:dddd4444": st["skipped_redundant"],
    }
    assert not_added["g:a:bbbb2222"]["Reason"] == "group type is read-only (AD)"
    assert not_added["g:t:cccc3333"]["Reason"] == "target is already a member"

    # No row for the metadata-less rule, the precheck row, or any other pair.
    all_rule_rows = [r for stem in VERBOSE_RULE_STEMS for r in read_rows(folder / f"{stem}-{TS}.csv")[1]]
    assert len(all_rule_rows) == 6
    assert not any(r["Source Rule ID"] == "nometa" for r in all_rule_rows)
    for stem in VERBOSE_RULE_STEMS:
        header, _rows = read_rows(folder / f"{stem}-{TS}.csv")
        assert header == rule_header(stem)

    # The pair with no actions still gets six files, all header-only.
    for stem in VERBOSE_STEMS:
        header, rows = read_rows(lonely_folder / f"{stem}-{TS}.csv")
        assert rows == []
        assert header


def _pairs_csv(tmp_path: Path) -> Path:
    """Input CSV with the single pair used by the backend fixture."""
    pairs_csv = tmp_path / "pairs.csv"
    pairs_csv.write_text(
        "srcAssetId,srcAssetName,dstAssetId,dstAssetName\n"
        f"{SRC},SrcHost,{DST},DstHost\n",
        encoding="utf-8",
    )
    return pairs_csv


def test_verbose_dry_run_writes_pair_folder_and_makes_only_gets(tmp_path: Path) -> None:
    fake = build_fake_backend()
    args = argparse.Namespace(input=str(_pairs_csv(tmp_path)), resume=None, apply=False,
                              verbose_dry_run=True)
    out_dir = tmp_path / "outputs" / "2026-01-01"

    rc = run_with_client(fake, lambda c: mma.run_forward(c, args, default_opts(), out_dir, TS))

    assert rc == 0
    assert set(fake.methods) == {"GET"}
    assert (out_dir / f"manual-mirror-plan-{TS}.csv").is_file()
    folder = out_dir / "SrcHost_to_DstHost"
    assert sorted(p.name for p in folder.iterdir()) == sorted(f"{s}-{TS}.csv" for s in VERBOSE_STEMS)

    def sources(stem: str) -> set[str]:
        return {r.get("Source Rule ID") or r.get("Group ID") for r in read_rows(folder / f"{stem}-{TS}.csv")[1]}

    assert sources("inbound-allow") == {"rule-owner-in", "rule-remote-in", "rule-deleted", "rule-inherited"}
    assert sources("outbound-block") == {"rule-owner-out"}
    assert sources("inbound-block") == set()
    assert sources("outbound-allow") == set()
    assert sources("groups-added") == {"g:c:aaaa1111"}
    assert sources("groups-not-added") == {"g:a:bbbb2222"}


def test_verbose_dry_run_with_apply_warns_and_writes_no_verbose_folder(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    fake = build_fake_backend()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method != "GET":
            fake.methods.append(request.method)
            return httpx.Response(200, json={"item": {"id": "new-1"}})
        return fake(request)

    args = argparse.Namespace(input=str(_pairs_csv(tmp_path)), resume=None, apply=True,
                              verbose_dry_run=True)
    out_dir = tmp_path / "outputs" / "2026-01-01"

    with caplog.at_level(logging.WARNING, logger="manual_mirror_assets"):
        run_with_client(handler, lambda c: mma.run_forward(c, args, default_opts(apply=True), out_dir, TS))

    assert "--verbose-dry-run only applies to dry runs" in caplog.text
    assert "POST" in fake.methods or "PUT" in fake.methods
    assert not (out_dir / "SrcHost_to_DstHost").exists()
    assert (out_dir / f"manual-mirror-results-{TS}.csv").is_file()


def test_format_ports_renders_protocol_any_and_group_type_ou() -> None:
    """Protocol 256 is "Any" in the spec; OU groups (g:u:) get a readable type."""
    assert mma._format_ports([{"protocolType": 256, "ports": ""}]) == "any"
    assert mma._format_ports([{"protocolType": 6, "ports": "443"}]) == "tcp/443"
    assert mma.group_type_word("g:u:abcd1234") == "OU"
    assert mma.group_type_word("g:i:abcd1234") == "i"


# ---------------------------------------------------------------------------
# Human-readable labels
# ---------------------------------------------------------------------------

CAMEL_CASE_RE = re.compile(r"[a-z][A-Z]")
CAMEL_ID_RE = re.compile(r"\b[a-z]+Ids?\b")


def test_rule_columns_headers_follow_direction() -> None:
    inbound = dict(mma.rule_columns("inbound"))
    outbound = dict(mma.rule_columns("outbound"))
    assert inbound["localEntityId"] == "Original Destination Asset ID (rule owner)"
    assert inbound["originalRemoteIds"] == "Original Source Asset IDs"
    assert inbound["newRemoteIds"] == "New Source Asset IDs"
    assert outbound["localEntityId"] == "Original Source Asset ID (rule owner)"
    assert outbound["originalRemoteIds"] == "Original Destination Asset IDs"
    assert outbound["newRemoteNames"] == "New Destination Asset Names"
    # The new rule owner (ID and name) is shown next to the original owner.
    assert inbound["newLocalEntityId"] == "New Destination Asset ID (rule owner)"
    assert inbound["newLocalEntityName"] == "New Destination Asset Name (rule owner)"
    assert outbound["newLocalEntityId"] == "New Source Asset ID (rule owner)"
    assert outbound["newLocalEntityName"] == "New Source Asset Name (rule owner)"


def test_rule_columns_exact_order_source_columns_first() -> None:
    """Source columns come first in both directions (inbound: remote then owner; outbound: owner then remote)."""
    common_head = ["Status", "Reason", "Copy Type", "Source Rule ID", "Rule State"]
    common_tail = ["Ports", "Processes", "Services", "Expires", "New Rule Description"]
    assert [label for _, label in mma.rule_columns("inbound")] == common_head + [
        "Original Source Asset IDs", "Original Source Asset Names",
        "New Source Asset IDs", "New Source Asset Names",
        "Original Destination Asset ID (rule owner)", "Original Destination Asset Name (rule owner)",
        "New Destination Asset ID (rule owner)", "New Destination Asset Name (rule owner)",
    ] + common_tail
    assert [label for _, label in mma.rule_columns("outbound")] == common_head + [
        "Original Source Asset ID (rule owner)", "Original Source Asset Name (rule owner)",
        "New Source Asset ID (rule owner)", "New Source Asset Name (rule owner)",
        "Original Destination Asset IDs", "Original Destination Asset Names",
        "New Destination Asset IDs", "New Destination Asset Names",
    ] + common_tail


def test_status_and_value_labels_map_and_pass_unknown_values_through() -> None:
    assert mma.status_label("planned") == "Will be created"
    assert mma.status_label("planned", "group") == "Will be added"
    assert mma.status_label("planned", "owner_rule") == "Will be created"
    assert mma.status_label("skipped_state") == mma.STATUS_LABELS["skipped_state"]
    assert mma.status_label("some_new_status") == "some_new_status"
    assert mma.category_label("owner_rule") == "Rule owned by the source asset"
    assert mma.category_label("mystery") == "mystery"
    assert mma.operation_label(mma.CONNECT_OPERATION) == "Update Connect (VPN) config"
    assert mma.operation_label("create_inbound_rule") == "Create inbound rule"
    assert mma.operation_label("mystery_op") == "mystery_op"


def test_copy_type_label_depends_on_direction() -> None:
    assert mma.copy_type_label("owner", "inbound") == "Owner copy (target becomes the rule owner)"
    assert mma.copy_type_label("remote", "inbound") == "Remote-side copy (target replaces the source)"
    assert mma.copy_type_label("remote", "outbound") == "Remote-side copy (target replaces the destination)"
    assert mma.copy_type_label("group_inherited", "inbound") == "Not copied (matched through a group)"
    assert mma.copy_type_label("", "inbound") == ""
    assert mma.copy_type_label("unexpected", "outbound") == "unexpected"


def test_rule_state_label_accepts_int_and_numeric_string_and_passes_unknown() -> None:
    assert mma.rule_state_label(1) == "Enabled"
    assert mma.rule_state_label("2") == "Disabled"
    assert mma.rule_state_label(3) == "Deleted by user"
    assert mma.rule_state_label(5) == "Pending review (auto)"
    assert mma.rule_state_label(7) == "Excluded by user"
    assert mma.rule_state_label(99) == "99"
    assert mma.rule_state_label("junk") == "junk"
    assert mma.rule_state_label(None) == ""
    assert mma.rule_state_label("") == ""


def test_expiry_label_never_for_empty_and_zero_and_exact_utc_for_epoch_ms() -> None:
    assert mma.expiry_label(None) == "Never"
    assert mma.expiry_label("") == "Never"
    assert mma.expiry_label(0) == "Never"
    assert mma.expiry_label("0") == "Never"
    # 1800000000 seconds after the epoch is 2027-01-15 08:00:00 UTC.
    assert mma.expiry_label(1_800_000_000_000) == "2027-01-15 08:00 UTC"
    assert mma.expiry_label("1800000000000") == "2027-01-15 08:00 UTC"
    assert mma.expiry_label("not-a-time") == "not-a-time"


def test_skip_reasons_and_connect_reason_have_no_api_field_names() -> None:
    for reason in mma.SKIP_REASON.values():
        assert not CAMEL_CASE_RE.search(reason), reason
    assert "exclusion list" in mma.SKIP_REASON[mma.KIND_EXCLUSION]
    config = {"allowedAssetIds": [{"id": SRC}], "excludedAssetIds": [], "allowedDestinations": []}
    reason = mma.connect_reason(config, PAIR)
    assert reason == "adds target next to source in: allowed assets"
    assert not CAMEL_CASE_RE.search(reason)


def test_write_labeled_csv_uses_labels_and_blanks_missing_keys(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "out.csv"
    mma.write_labeled_csv(path, (("a", "First Col"), ("b", "Second Col")),
                          [{"a": "1"}, {"a": "2", "b": "3"}])
    header, rows = read_rows(path)
    assert header == ["First Col", "Second Col"]
    assert rows == [{"First Col": "1", "Second Col": ""}, {"First Col": "2", "Second Col": "3"}]


def test_planned_rule_rows_carry_new_names_and_ids_and_skipped_rows_are_blank() -> None:
    opts = default_opts()
    target = mma.TargetIndex()
    planned: set[tuple] = set()
    inbound_remote = make_rule("in-remote", "a:w:Y", [SRC])
    owner = make_rule("out-owner", SRC, ["a:w:X", "a:w:Y"], action=2, ipsec=None)
    owner["remoteEntityInfos"] = [{"id": "a:w:X", "name": "XHost"}]
    inherited = make_rule("in-inherited", "a:w:Y", ["a:w:Z"])

    remote_actions = mma.plan_rule_actions(inbound_remote, "inbound", PAIR, opts, target, planned)
    owner_actions = mma.plan_rule_actions(owner, "outbound", PAIR, opts, target, planned)
    skipped_actions = mma.plan_rule_actions(inherited, "inbound", PAIR, opts, target, planned)

    remote_row = mma._verbose_rule_row(remote_actions[0])
    assert remote_row["status"] == mma.STATUS_LABELS["planned"]
    assert remote_row["newRemoteNames"] == "DstHost"
    # Remote-side copy: the rule owner is unchanged.
    assert remote_row["newLocalEntityId"] == "a:w:Y"
    assert remote_row["newLocalEntityName"] == remote_row["localEntityName"]

    owner_row = mma._verbose_rule_row(owner_actions[0])
    assert owner_row["newRemoteIds"] == "a:w:X; a:w:Y"
    assert owner_row["newRemoteNames"] == "XHost; a:w:Y"
    # Owner copy: the target becomes the rule owner, shown by id and by name.
    assert owner_row["localEntityId"] == SRC
    assert owner_row["newLocalEntityId"] == DST
    assert owner_row["newLocalEntityName"] == "DstHost"

    skipped_row = mma._verbose_rule_row(skipped_actions[0])
    assert skipped_row["status"] == mma.STATUS_LABELS["skipped_group_inherited"]
    assert skipped_row["newRemoteNames"] == ""
    assert skipped_row["newRemoteIds"] == ""
    assert skipped_row["newLocalEntityId"] == ""
    assert skipped_row["newLocalEntityName"] == ""


def test_verbose_inbound_and_outbound_files_use_direction_headers(tmp_path: Path) -> None:
    opts = default_opts()
    target = mma.TargetIndex()
    planned: set[tuple] = set()
    actions = mma.plan_rule_actions(make_rule("in-owner", SRC, ["a:w:X"]), "inbound", PAIR,
                                    opts, target, planned)
    actions += mma.plan_rule_actions(make_rule("out-owner", SRC, ["a:w:X"], action=2, ipsec=None),
                                     "outbound", PAIR, opts, target, planned)
    mma.write_verbose_reports(actions, [PAIR], tmp_path, TS)
    folder = tmp_path / "SrcHost_to_DstHost"

    inbound_header, _ = read_rows(folder / f"inbound-allow-{TS}.csv")
    outbound_header, _ = read_rows(folder / f"outbound-block-{TS}.csv")
    assert "Original Destination Asset ID (rule owner)" in inbound_header
    assert "Original Source Asset IDs" in inbound_header
    assert "Original Source Asset ID (rule owner)" not in inbound_header  # inbound owner is the destination
    assert "Original Source Asset ID (rule owner)" in outbound_header
    assert "Original Destination Asset IDs" in outbound_header
    assert inbound_header == rule_header("inbound-allow")
    assert outbound_header == rule_header("outbound-block")


def test_verbose_dry_run_csv_headers_and_values_are_human_readable(tmp_path: Path) -> None:
    fake = build_fake_backend()
    args = argparse.Namespace(input=str(_pairs_csv(tmp_path)), resume=None, apply=False,
                              verbose_dry_run=True)
    out_dir = tmp_path / "outputs" / "2026-01-01"
    run_with_client(fake, lambda c: mma.run_forward(c, args, default_opts(), out_dir, TS))

    csv_paths = sorted(out_dir.rglob("*.csv"))
    assert len(csv_paths) == 1 + len(VERBOSE_STEMS)
    for path in csv_paths:
        header, rows = read_rows(path)
        assert header, path
        for name in header:
            assert not CAMEL_CASE_RE.search(name), (path.name, name)
            assert not CAMEL_ID_RE.search(name), (path.name, name)
        for row in rows:
            for value in row.values():
                assert value not in mma.STATUS_LABELS, (path.name, value)

    plan_header, plan_rows = read_rows(out_dir / f"manual-mirror-plan-{TS}.csv")
    assert plan_header == [label for _key, label in mma.PLAN_COLUMNS]
    assert "Status" in plan_header and "Category" in plan_header
    statuses = {r["Status"] for r in plan_rows}
    assert mma.STATUS_LABELS["planned"] in statuses
    assert "Will be added" in statuses


def test_apply_results_csv_keeps_machine_headers_and_values(tmp_path: Path) -> None:
    fake = build_fake_backend()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method != "GET":
            fake.methods.append(request.method)
            return httpx.Response(200, json={"item": {"id": "new-1"}})
        return fake(request)

    args = argparse.Namespace(input=str(_pairs_csv(tmp_path)), resume=None, apply=True,
                              verbose_dry_run=False)
    out_dir = tmp_path / "outputs" / "2026-01-01"
    run_with_client(handler, lambda c: mma.run_forward(c, args, default_opts(apply=True), out_dir, TS))

    results = out_dir / f"manual-mirror-results-{TS}.csv"
    with results.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        assert reader.fieldnames == list(mma.RESULT_COLUMNS)
    assert rows
    assert {r["status"] for r in rows} <= set(mma.STATUS_LABELS)  # machine codes, not labels
    assert "created" in {r["status"] for r in rows}


def test_read_result_rows_rejects_humanized_dry_run_plan(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    plan = tmp_path / "manual-mirror-plan-x.csv"
    mma.write_labeled_csv(plan, mma.PLAN_COLUMNS, [{"Status": "Will be created"}])
    with caplog.at_level(logging.ERROR, logger="manual_mirror_assets"):
        with pytest.raises(SystemExit):
            mma.read_result_rows(plan)
    assert "looks like a dry-run plan; pass the results CSV written by an --apply run" in caplog.text


def test_read_result_rows_reads_machine_results_csv(tmp_path: Path) -> None:
    results = tmp_path / "results.csv"
    mma.write_csv(results, mma.RESULT_COLUMNS, [{"status": "created", "category": "owner_rule"}])
    rows = mma.read_result_rows(results)
    assert rows[0]["status"] == "created"
    assert rows[0]["category"] == "owner_rule"
