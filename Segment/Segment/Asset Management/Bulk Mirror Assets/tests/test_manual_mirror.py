"""Unit and mock-transport tests for manual_mirror_assets.py."""

from __future__ import annotations

import argparse
import asyncio
import csv
import importlib.util
import json
import sys
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
    args = argparse.Namespace(input=str(pairs_csv), resume=None, apply=False)
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
    statuses = {(r["category"], r["sourceObjectId"]): r["status"] for r in rows}
    assert statuses[("precheck", SRC)] == "warning"  # AD source to non-AD target
    assert statuses[("group", "g:a:bbbb2222")] == "skipped_readonly"
    assert statuses[("group", "g:c:aaaa1111")] == "planned"
    assert statuses[("owner_rule", "rule-owner-in")] == "planned"
    assert statuses[("owner_rule", "rule-owner-out")] == "planned"
    assert statuses[("inbound_remote_rule", "rule-remote-in")] == "planned"
    assert statuses[("owner_rule", "rule-deleted")] == "skipped_state"
    assert statuses[("inbound_remote_rule", "rule-inherited")] == "skipped_group_inherited"
    planned_bodies = [r for r in rows if r["status"] == "planned" and r["category"] == "inbound_remote_rule"]
    assert json.loads(planned_bodies[0]["bodyJson"])["remoteEntityIdsList"] == [DST]


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
