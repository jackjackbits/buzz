//! Repository-complete structural guard for production writes to community-fenced tables.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use sqlparser::ast::{
    BinaryOperator, Expr, FromTable, FunctionArg, FunctionArgExpr, FunctionArguments, Insert,
    ObjectName, Query, Select, SetExpr, Statement, TableFactor, TableObject, TableWithJoins, Value,
};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

const AUTHORITY: &[&str] = buzz_db::deletion::EXPECTED_SCOPED_TABLES;
const EXEMPT_CRATES: &[&str] = &[
    // Browser/CLI/protocol crates do not link SQLx or execute PostgreSQL.
    "buzz-acp",
    "buzz-agent",
    "buzz-backend-kubernetes",
    "buzz-cli",
    "buzz-conformance",
    "buzz-core",
    "buzz-dev-mcp",
    "buzz-media",
    "buzz-pair-relay",
    "buzz-pairing-cli",
    "buzz-persona",
    "buzz-pubsub",
    "buzz-push-gateway", // deployment-global gateway tables only
    "buzz-relay-mesh",
    "buzz-sdk",
    "buzz-test-client", // test-only client; production source has no SQL writers
    "buzz-voice",
    "buzz-workflow",
    "buzz-ws-client",
    "git-credential-nostr",
    "git-sign-nostr",
    "sprig",
];
const NAMED_SQL_WRITES: &[(&str, &str, &str)] = &[(
    "crates/buzz-db/src/reaction.rs",
    "ADD_REACTION_SQL",
    "ON CONFLICT (community_id, event_created_at, event_id, pubkey, emoji)",
)];

const CONDITIONAL_SQL_WRITES: &[(&str, &str, &[&str])] = &[(
    "crates/buzz-db/src/lib.rs",
    "let statement = if hard_delete_superseded",
    &[
        "DELETE FROM events",
        "UPDATE events SET deleted_at = NOW()",
        "WHERE community_id = $1 AND kind = $2 AND pubkey = $3 AND d_tag = $4",
    ],
)];

const DYNAMIC_WRITES: &[(&str, &str, &str)] = &[
    (
        "crates/buzz-db/src/channel.rs",
        "UPDATE channels SET {}",
        "WHERE community_id = ${param_idx}",
    ),
    (
        "crates/buzz-db/src/deletion.rs",
        "DELETE FROM {table}",
        "WHERE community_id = $1",
    ),
    (
        "crates/buzz-db/src/lib.rs",
        "INSERT INTO event_mentions",
        "push_bind(community_id.as_uuid())",
    ),
    (
        "crates/buzz-db/src/user.rs",
        "UPDATE users SET {}",
        "WHERE community_id = ${param_idx}",
    ),
];

// PostgreSQL syntax intentionally unsupported by sqlparser 0.62. Each entry is
// an exact, reviewed statement fingerprint; source edits fail closed until the
// statement either parses or this inventory is deliberately updated.
const PARSER_EXCEPTIONS: &[(&str, &str, &str)] = &[
    (
        "crates/buzz-db/src/deletion.rs",
        "WITH candidate AS",
        "WHERE request.id = candidate.id",
    ),
    (
        "crates/buzz-db/src/push.rs",
        "WITH target AS",
        "community_write_allowed(community_id)",
    ),
    (
        "crates/buzz-db/src/push.rs",
        "WITH candidates AS",
        "WHERE o.community_id = $1",
    ),
    (
        "crates/buzz-db/src/lib.rs",
        "ON CONFLICT (lower(host))",
        "communities.deletion_state = 'active'",
    ),
    (
        "crates/buzz-db/src/lib.rs",
        "ON CONFLICT (lower(host)) DO NOTHING",
        "RETURNING id, host",
    ),
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_owned()
}

fn authority() -> BTreeSet<String> {
    AUTHORITY.iter().map(|table| (*table).to_owned()).collect()
}

fn workspace_crates() -> BTreeSet<String> {
    fs::read_dir(repo_root().join("crates"))
        .expect("read crates directory")
        .filter_map(Result::ok)
        .filter(|entry| entry.path().join("Cargo.toml").is_file())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect()
}

fn production_roots() -> Vec<PathBuf> {
    let exempt = EXEMPT_CRATES.iter().copied().collect::<BTreeSet<_>>();
    let crates = workspace_crates();
    let unknown_exempt = exempt
        .iter()
        .filter(|name| !crates.contains(**name))
        .copied()
        .collect::<Vec<_>>();
    assert!(
        unknown_exempt.is_empty(),
        "stale exempt crates: {unknown_exempt:?}"
    );
    crates
        .into_iter()
        .filter(|name| !exempt.contains(name.as_str()))
        .map(|name| repo_root().join("crates").join(name).join("src"))
        .filter(|path| path.is_dir())
        .collect()
}

fn ast_matches_for_rule(roots: &[PathBuf], rule: &str) -> Vec<serde_json::Value> {
    let mut command = Command::new(repo_root().join("bin/ast-grep"));
    command
        .arg("scan")
        .arg("--rule")
        .arg(repo_root().join(rule))
        .arg("--json=stream");
    command.args(roots);
    let output = command.output().expect("run ast-grep");
    assert!(
        output.status.success(),
        "ast-grep failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("ast-grep utf8")
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str(line).expect("ast-grep json line"))
        .collect()
}

fn ast_matches(roots: &[PathBuf]) -> Vec<serde_json::Value> {
    ast_matches_for_rule(roots, "scripts/lints/community_fenced_writes.yml")
}

fn test_module_ranges(roots: &[PathBuf]) -> BTreeMap<PathBuf, Vec<(u64, u64)>> {
    let mut ranges = BTreeMap::<PathBuf, Vec<(u64, u64)>>::new();
    for matched in ast_matches_for_rule(roots, "scripts/lints/community_test_modules.yml") {
        let path = PathBuf::from(matched["file"].as_str().expect("test module file"));
        let start = matched["range"]["byteOffset"]["start"]
            .as_u64()
            .expect("start offset");
        let end = matched["range"]["byteOffset"]["end"]
            .as_u64()
            .expect("end offset");
        ranges.entry(path).or_default().push((start, end));
    }
    ranges
}

fn rust_string_value(token: &str) -> Option<String> {
    if let Ok(literal) = litrs::StringLit::parse(token) {
        return Some(literal.value().to_owned());
    }
    if token.starts_with('"') && token.ends_with('"') {
        let continued = regex_lite::Regex::new(
            r"\\
[ \t]*",
        )
        .expect("line-continuation regex")
        .replace_all(token, "");
        return serde_json::from_str(&continued).ok();
    }
    None
}

fn basename(name: &ObjectName) -> String {
    name.0
        .last()
        .and_then(|part| part.as_ident())
        .map(|ident| ident.value.to_ascii_lowercase())
        .unwrap_or_default()
}

fn table_factor_name(factor: &TableFactor) -> Option<String> {
    match factor {
        TableFactor::Table { name, .. } => Some(basename(name)),
        _ => None,
    }
}

fn target_aliases(factor: &TableFactor, target: &str) -> BTreeSet<String> {
    let mut aliases = BTreeSet::from([target.to_owned()]);
    if let TableFactor::Table {
        alias: Some(alias), ..
    } = factor
    {
        aliases.insert(alias.name.value.to_ascii_lowercase());
    }
    aliases
}

fn query_sources(query: &Query) -> BTreeSet<String> {
    fn collect_select(select: &Select, out: &mut BTreeSet<String>) {
        for TableWithJoins { relation, joins } in &select.from {
            if let Some(name) = table_factor_name(relation) {
                out.insert(name);
            }
            for join in joins {
                if let Some(name) = table_factor_name(&join.relation) {
                    out.insert(name);
                }
            }
        }
    }
    let mut out = BTreeSet::new();
    match query.body.as_ref() {
        SetExpr::Select(select) => collect_select(select, &mut out),
        SetExpr::Query(query) => out.extend(query_sources(query)),
        SetExpr::SetOperation { left, right, .. } => {
            if let SetExpr::Select(select) = left.as_ref() {
                collect_select(select, &mut out);
            }
            if let SetExpr::Select(select) = right.as_ref() {
                collect_select(select, &mut out);
            }
        }
        _ => {}
    }
    out
}

fn is_community_column(expr: &Expr, aliases: &BTreeSet<String>) -> bool {
    match expr {
        Expr::Identifier(ident) => ident.value.eq_ignore_ascii_case("community_id"),
        Expr::CompoundIdentifier(parts) if parts.len() >= 2 => {
            parts
                .last()
                .is_some_and(|part| part.value.eq_ignore_ascii_case("community_id"))
                && parts
                    .get(parts.len() - 2)
                    .is_some_and(|part| aliases.contains(&part.value.to_ascii_lowercase()))
        }
        _ => false,
    }
}

fn is_placeholder(expr: &Expr) -> bool {
    matches!(expr, Expr::Value(value) if matches!(&value.value, Value::Placeholder(_)))
}

fn is_allowed_function(expr: &Expr, aliases: &BTreeSet<String>) -> bool {
    let Expr::Function(function) = expr else {
        return false;
    };
    if basename(&function.name) != "community_write_allowed" {
        return false;
    }
    let FunctionArguments::List(arguments) = &function.args else {
        return false;
    };
    matches!(arguments.args.as_slice(), [FunctionArg::Unnamed(FunctionArgExpr::Expr(argument))] if is_community_column(argument, aliases))
}

fn predicate_is_directly_gated(selection: Option<&Expr>, aliases: &BTreeSet<String>) -> bool {
    let Some(selection) = selection else {
        return false;
    };
    match selection {
        Expr::Nested(expr) => predicate_is_directly_gated(Some(expr), aliases),
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And | BinaryOperator::Or,
            right,
        } => {
            predicate_is_directly_gated(Some(left), aliases)
                || predicate_is_directly_gated(Some(right), aliases)
        }
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } => {
            (is_community_column(left, aliases) && is_placeholder(right))
                || (is_placeholder(left) && is_community_column(right, aliases))
        }
        Expr::InSubquery { subquery, .. } | Expr::Subquery(subquery) => {
            query_is_tenant_bound_or_gated(subquery)
        }
        expr => is_allowed_function(expr, aliases),
    }
}

fn query_is_tenant_bound_or_gated(query: &Query) -> bool {
    match query.body.as_ref() {
        SetExpr::Select(select) => {
            let aliases = select
                .from
                .iter()
                .filter_map(|table| {
                    table_factor_name(&table.relation)
                        .map(|target| target_aliases(&table.relation, &target))
                })
                .flatten()
                .collect::<BTreeSet<_>>();
            predicate_is_directly_gated(select.selection.as_ref(), &aliases)
        }
        SetExpr::Query(query) => query_is_tenant_bound_or_gated(query),
        SetExpr::SetOperation { left, right, .. } => {
            let branch = |set: &SetExpr| match set {
                SetExpr::Select(select) => {
                    let aliases = select
                        .from
                        .iter()
                        .filter_map(|table| {
                            table_factor_name(&table.relation)
                                .map(|target| target_aliases(&table.relation, &target))
                        })
                        .flatten()
                        .collect::<BTreeSet<_>>();
                    predicate_is_directly_gated(select.selection.as_ref(), &aliases)
                }
                SetExpr::Query(query) => query_is_tenant_bound_or_gated(query),
                _ => false,
            };
            branch(left) && branch(right)
        }
        SetExpr::Values(_) => true,
        _ => false,
    }
}

fn mutation_violation(statement: &Statement, fenced: &BTreeSet<String>) -> Option<String> {
    match statement {
        Statement::Delete(delete) => {
            let tables = match &delete.from {
                FromTable::WithFromKeyword(tables) | FromTable::WithoutKeyword(tables) => tables,
            };
            let factor = &tables.first()?.relation;
            let target = table_factor_name(factor)?;
            if !fenced.contains(&target) {
                return None;
            }
            let aliases = target_aliases(factor, &target);
            (!predicate_is_directly_gated(delete.selection.as_ref(), &aliases)).then(|| {
                format!("fleet DELETE from {target} lacks a direct tenant predicate or community_write_allowed")
            })
        }
        Statement::Update(update) => {
            let factor = &update.table.relation;
            let target = table_factor_name(factor)?;
            if !fenced.contains(&target) {
                return None;
            }
            let aliases = target_aliases(factor, &target);
            (!predicate_is_directly_gated(update.selection.as_ref(), &aliases)).then(|| {
                format!("fleet UPDATE of {target} lacks a direct tenant predicate or community_write_allowed")
            })
        }
        Statement::Insert(Insert { table, source, .. }) => {
            let TableObject::TableName(table_name) = table else {
                return None;
            };
            let target = basename(table_name);
            if !fenced.contains(&target) {
                return None;
            }
            let Some(source) = source else { return None };
            let sources = query_sources(source);
            if sources.iter().any(|source| fenced.contains(source))
                && !query_is_tenant_bound_or_gated(source)
            {
                return Some(format!(
                    "fleet INSERT SELECT into {target} reads fenced sources without a direct gate"
                ));
            }
            None
        }
        _ => None,
    }
}

fn parse_sql(sql: &str) -> Result<Vec<Statement>, String> {
    Parser::parse_sql(&PostgreSqlDialect {}, sql).map_err(|error| error.to_string())
}

fn inspect_matches(matches: &[serde_json::Value], roots: &[PathBuf]) -> Vec<String> {
    let fenced = authority();
    let root = repo_root();
    let mut violations = Vec::new();
    let mut observed_parser_exceptions = BTreeSet::new();
    let test_ranges = test_module_ranges(roots);
    let production_files = roots
        .iter()
        .flat_map(|source| {
            walkdir::WalkDir::new(source)
                .into_iter()
                .filter_map(Result::ok)
        })
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "rs"))
        .map(|entry| entry.into_path())
        .collect::<BTreeSet<_>>();
    assert!(!production_files.is_empty());

    for matched in matches {
        let path = PathBuf::from(matched["file"].as_str().expect("match file"));
        assert!(
            production_files.contains(&path),
            "match escaped production roots: {path:?}"
        );
        let offset = matched["range"]["byteOffset"]["start"]
            .as_u64()
            .expect("match offset");
        if test_ranges.get(&path).is_some_and(|ranges| {
            ranges
                .iter()
                .any(|(start, end)| *start <= offset && offset < *end)
        }) {
            continue;
        }
        let line = matched["range"]["start"]["line"].as_u64().unwrap_or(0) + 1;
        let sql_token = matched["metaVariables"]["single"]["SQL"]["text"]
            .as_str()
            .expect("SQL metavariable");
        let Some(sql) = rust_string_value(sql_token) else {
            let relative = path.strip_prefix(&root).unwrap_or(&path).to_string_lossy();
            let inventoried = NAMED_SQL_WRITES.iter().any(|(file, symbol, guard)| {
                relative == *file
                    && sql_token.contains(symbol)
                    && fs::read_to_string(&path)
                        .is_ok_and(|source| source.contains(symbol) && source.contains(guard))
            });
            let conditional = CONDITIONAL_SQL_WRITES.iter().any(|(file, symbol, guards)| {
                relative == *file
                    && sql_token == "statement"
                    && fs::read_to_string(&path).is_ok_and(|source| {
                        source.contains(symbol) && guards.iter().all(|guard| source.contains(guard))
                    })
            });
            if !inventoried && !conditional && !sql_token.contains("AssertSqlSafe") {
                violations.push(format!(
                    "{relative}:{line}: unclassified non-literal SQL expression: {sql_token}"
                ));
            }
            continue;
        };
        match parse_sql(&sql) {
            Ok(statements) => {
                for statement in statements {
                    if let Some(message) = mutation_violation(&statement, &fenced) {
                        violations.push(format!(
                            "{}:{line}: {message}",
                            path.strip_prefix(&root).unwrap_or(&path).display()
                        ));
                    }
                }
            }
            Err(error)
                if sql.to_ascii_lowercase().contains("insert into")
                    || sql.to_ascii_lowercase().contains("update ")
                    || sql.to_ascii_lowercase().contains("delete from") =>
            {
                let relative = path.strip_prefix(&root).unwrap_or(&path).to_string_lossy();
                let excepted = PARSER_EXCEPTIONS.iter().any(|(file, start, guard)| {
                    relative == *file && sql.contains(start) && sql.contains(guard)
                });
                if excepted {
                    observed_parser_exceptions.insert(relative.into_owned());
                } else {
                    violations.push(format!(
                        "{relative}:{line}: production write SQL did not parse: {error}"
                    ));
                }
            }
            Err(_) => {}
        }
    }

    for (relative, write_marker, scope_marker) in DYNAMIC_WRITES {
        let text = fs::read_to_string(root.join(relative)).expect("read dynamic writer");
        if !text.contains(write_marker) || !text.contains(scope_marker) {
            violations.push(format!(
                "{relative}: dynamic writer contract changed: {write_marker:?} / {scope_marker:?}"
            ));
        }
    }
    for (relative, symbol, guards) in CONDITIONAL_SQL_WRITES {
        let text = fs::read_to_string(root.join(relative)).expect("read conditional SQL writer");
        if !text.contains(symbol) || !guards.iter().all(|guard| text.contains(guard)) {
            violations.push(format!(
                "{relative}: conditional SQL writer contract changed: {symbol:?} / {guards:?}"
            ));
        }
    }
    for (relative, symbol, guard) in NAMED_SQL_WRITES {
        let text = fs::read_to_string(root.join(relative)).expect("read named SQL writer");
        if !text.contains(symbol) || !text.contains(guard) {
            violations.push(format!(
                "{relative}: named SQL writer contract changed: {symbol:?} / {guard:?}"
            ));
        }
    }
    violations
}

#[test]
fn production_fenced_writers_are_structurally_tenant_bound_or_gated() {
    let roots = production_roots();
    let matches = ast_matches(&roots);
    let violations = inspect_matches(&matches, &roots);
    assert!(
        violations.is_empty(),
        "community fenced-writer violations:\n{}",
        violations.join("\n")
    );
}

#[test]
fn scanner_rejects_calibrated_bad_shapes_through_the_real_extractor() {
    let fixture = repo_root().join("crates/buzz-db/tests/fixtures/community_fenced_writes");
    let matches = ast_matches(std::slice::from_ref(&fixture));
    let violations = inspect_matches(&matches, &[fixture]);
    assert!(
        violations.iter().any(|v| v.contains("bad_insert_select")),
        "fleet INSERT SELECT control escaped: {violations:?}"
    );
    assert!(
        violations
            .iter()
            .any(|v| v.contains("bad_unrelated_subquery")),
        "unrelated-subquery DELETE control escaped: {violations:?}"
    );
    assert!(
        !violations.iter().any(|v| v.contains("good_tenant_delete")),
        "tenant-bound control was rejected: {violations:?}"
    );
    assert!(
        !violations.iter().any(|v| v.contains("good_gated_delete")),
        "gated control was rejected: {violations:?}"
    );
}
