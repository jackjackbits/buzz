#!/usr/bin/env python3
"""Structurally inventory production SQLx writes to community-fenced tables.

ast-grep locates Rust call expressions, so multiline/raw strings and wrapper
formatting cannot disappear behind line-oriented grep. This classifier then
rejects fleet-wide UPDATE/DELETE statements unless the mutating statement
consumes community_write_allowed(community_id). Tenant-bound statements must
bind their community_id predicate directly. Dynamic SQL builders are tracked by
an explicit source inventory because their final SQL is assembled across calls.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULE = ROOT / "scripts/lints/community_fenced_writes.yml"
SOURCE_ROOTS = [ROOT / "crates/buzz-db/src", ROOT / "crates/buzz-audit/src", ROOT / "crates/buzz-relay/src"]
FENCED_TABLES = {
    "api_tokens", "archived_identities", "audit_log", "channel_members", "channels",
    "community_bans", "delivery_log", "event_mentions", "events", "git_repo_names",
    "join_policy_acceptances", "moderation_actions", "moderation_reports",
    "parameterized_event_watermarks", "product_feedback", "pubkey_allowlist",
    "push_leases", "push_match_queue", "push_wake_outbox", "rate_limit_violations",
    "reactions", "relay_invites", "relay_members", "scheduled_workflow_fires",
    "subscriptions", "thread_metadata", "users", "workflow_approvals", "workflow_runs",
    "workflows",
}
# Production dynamic write builders whose community binding was manually reviewed.
# The check fails if one moves or a new dynamic write builder appears.
DYNAMIC_WRITE_INVENTORY = {
    ("crates/buzz-db/src/channel.rs", "UPDATE channels SET {}", "WHERE community_id = ${param_idx}"),
    ("crates/buzz-db/src/deletion.rs", "DELETE FROM {table}", "WHERE community_id = $1"),
    ("crates/buzz-db/src/lib.rs", "INSERT INTO event_mentions", "push_bind(community_id.as_uuid())"),
    ("crates/buzz-db/src/user.rs", "UPDATE users SET {}", "WHERE community_id = ${param_idx}"),
}

WRITE_RE = re.compile(r"\b(update|delete\s+from|insert\s+into|merge\s+into)\s+(?:only\s+)?(?:public\.)?\"?([a-z_][a-z0-9_]*)", re.I)
BOUND_RE = re.compile(
    r"(?:\b[a-z_][a-z0-9_]*\.)?community_id\s*(?:=|is\s+not\s+distinct\s+from)\s*(?:any\s*\(\s*)?\$\d+"
    r"|\$\d+\s*=\s*(?:\b[a-z_][a-z0-9_]*\.)?community_id",
    re.I,
)


def rust_string_value(token: str) -> str | None:
    raw = re.fullmatch(r'r(#{0,16})"(.*)"\1', token, re.S)
    if raw:
        return raw.group(2)
    if token.startswith('"'):
        try:
            return ast.literal_eval(token)
        except (SyntaxError, ValueError):
            return None
    return None


def production_prefix(path: Path) -> str:
    text = path.read_text()
    marker = text.find("#[cfg(test)]")
    return text if marker < 0 else text[:marker]


def ast_matches() -> list[dict]:
    command = [str(ROOT / "bin/ast-grep"), "scan", "--rule", str(RULE), "--json=stream", *map(str, SOURCE_ROOTS)]
    try:
        completed = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=True)
    except FileNotFoundError:
        raise SystemExit("bin/ast-grep is required; restore the repository Hermit package links")
    except subprocess.CalledProcessError as error:
        sys.stderr.write(error.stderr)
        raise SystemExit(error.returncode)
    return [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]


def literal_from_match(match: dict) -> str | None:
    sql = match.get("metaVariables", {}).get("single", {}).get("SQL", {}).get("text")
    return rust_string_value(sql) if sql is not None else None


def classify(matches: list[dict]) -> tuple[list[str], set[tuple[str, int, str]]]:
    violations: list[str] = []
    inventory: set[tuple[str, int, str]] = set()
    for match in matches:
        relative = str(Path(match["file"]).resolve().relative_to(ROOT))
        line = match["range"]["start"]["line"] + 1
        source_path = ROOT / relative
        source = source_path.read_text()
        # Exclude only the file's test module, not individual cfg(test) helpers
        # that may occur inside the production impl before it.
        test_module = re.search(r"(?m)^#\[cfg\(test\)\]\s*\n(?:pub\s+)?mod\s+tests\b", source)
        if test_module and match["range"]["byteOffset"]["start"] > test_module.start():
            continue
        sql = literal_from_match(match)
        if sql is None:
            continue
        normalized = re.sub(r"\s+", " ", sql).strip().lower()
        writes = [(op.lower(), table.lower()) for op, table in WRITE_RE.findall(normalized) if table.lower() in FENCED_TABLES]
        if not writes:
            continue
        for operation, table in writes:
            inventory.add((relative, line, table))
            if operation in {"update", "delete from", "merge into"}:
                fleet = not BOUND_RE.search(normalized)
                if fleet and "community_write_allowed(" not in normalized:
                    violations.append(
                        f"{relative}:{line}: fleet-wide {operation} of fenced table {table} "
                        "must consume community_write_allowed(community_id) in the writing statement"
                    )
    return violations, inventory


def dynamic_violations() -> list[str]:
    violations: list[str] = []
    observed: set[tuple[str, str, str]] = set()
    for relative, write_marker, scope_marker in DYNAMIC_WRITE_INVENTORY:
        text = production_prefix(ROOT / relative)
        if write_marker in text and scope_marker in text:
            observed.add((relative, write_marker, scope_marker))
        else:
            violations.append(f"{relative}: reviewed dynamic fenced-write contract changed: {write_marker!r} / {scope_marker!r}")

    dynamic_calls = [
        ("sqlx::query(AssertSqlSafe", re.compile(r"sqlx::(?:query|query_scalar|query_as)(?:<[^;]+?>)?\s*\(\s*(?:sqlx::)?AssertSqlSafe\s*\(")),
        ("QueryBuilder::new", re.compile(r"QueryBuilder::new\s*\(")),
    ]
    for root in SOURCE_ROOTS:
        for path in root.rglob("*.rs"):
            text = production_prefix(path)
            relative = str(path.relative_to(ROOT))
            for label, pattern in dynamic_calls:
                for match in pattern.finditer(text):
                    # Inspect the local construction window, not the whole file;
                    # a read builder must not be confused with an unrelated write.
                    window = text[match.start() : match.start() + 900]
                    if not any(
                        re.search(rf"(?:UPDATE|DELETE FROM|INSERT INTO)\s+{table}\b", window, re.I)
                        for table in FENCED_TABLES
                    ):
                        continue
                    if not any(
                        entry[0] == relative
                        and entry in observed
                        and entry[1] in window
                        and entry[2] in text[max(0, match.start() - 500) : match.start() + 1800]
                        for entry in DYNAMIC_WRITE_INVENTORY
                    ):
                        line = text.count("\n", 0, match.start()) + 1
                        violations.append(f"{relative}:{line}: unclassified dynamic SQL write builder ({label})")
    return sorted(set(violations))


def self_test(matches: list[dict]) -> None:
    def violation(sql: str) -> bool:
        normalized = re.sub(r"\s+", " ", sql).strip().lower()
        writes = [(op.lower(), table.lower()) for op, table in WRITE_RE.findall(normalized) if table.lower() in FENCED_TABLES]
        return any(op in {"update", "delete from", "merge into"} and not BOUND_RE.search(normalized) and "community_write_allowed(" not in normalized for op, _ in writes)

    assert violation("DELETE FROM relay_invites WHERE expires_at < $1")  # known-bad positive control
    assert violation("WITH c AS (SELECT * FROM events) UPDATE events SET d_tag='' WHERE d_tag IS NULL")
    assert violation("DELETE FROM scheduled_workflow_fires WHERE claimed_at < $1")
    assert not violation("DELETE FROM relay_invites WHERE community_id=$1 AND expires_at < $2")
    assert not violation("DELETE FROM relay_invites WHERE expires_at < $1 AND community_write_allowed(community_id)")
    assert not violation("SELECT * FROM relay_invites")

    # Calibrate the real structural extractor in both directions, not only the
    # SQL classifier: the known production writers must be in its inventory.
    expected_sites = {
        ("crates/buzz-db/src/channel.rs", "channels"),
        ("crates/buzz-db/src/lib.rs", "events"),
        ("crates/buzz-db/src/push.rs", "push_match_queue"),
        ("crates/buzz-db/src/relay_invite.rs", "relay_invites"),
        ("crates/buzz-db/src/workflow.rs", "scheduled_workflow_fires"),
    }
    _, inventory = classify(matches)
    observed_sites = {(relative, table) for relative, _, table in inventory}
    missing = expected_sites - observed_sites
    assert not missing, f"structural extractor missed calibrated production sites: {sorted(missing)}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--list", action="store_true", help="print the classified production write inventory")
    args = parser.parse_args()
    matches = ast_matches()
    self_test(matches)
    violations, inventory = classify(matches)
    violations.extend(dynamic_violations())
    if args.list:
        for relative, line, table in sorted(inventory):
            print(f"{relative}:{line}: {table}")
    if violations:
        print("community fenced-writer structural lint failed:", file=sys.stderr)
        for violation in violations:
            print(f"- {violation}", file=sys.stderr)
        return 1
    print(f"community fenced-writer structural lint passed ({len(inventory)} literal write sites classified)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
