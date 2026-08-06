//! Repository-complete structural guard for production writes to community-fenced tables.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};
use sqlparser::ast::{
    BinaryOperator, Expr, FromTable, FunctionArg, FunctionArgExpr, FunctionArguments, Insert,
    ObjectName, Query, Select, SelectItem, SetExpr, Statement, TableFactor, TableObject, Value,
};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

const AUTHORITY: &[&str] = buzz_db::deletion::EXPECTED_SCOPED_TABLES;
const NAMED_SQL: &[(&str, &str, &str)] = &[(
    "crates/buzz-db/src/reaction.rs",
    "ADD_REACTION_SQL",
    "ADD_REACTION_SQL",
)];

const CONDITIONAL_SQL: &[(&str, &str, &str)] = &[(
    "crates/buzz-db/src/lib.rs",
    "replace_parameterized_event",
    "statement",
)];

#[derive(Clone, Copy)]
struct DynamicSqlInventory {
    file: &'static str,
    owner: &'static str,
    argument: &'static str,
    /// SHA-256 of the complete owning function source.
    /// This binds a dynamic execution to the SQL-producing dataflow, not merely
    /// to a local identifier such as `sql` at the execution call.
    owner_fingerprint: &'static str,
}

const DYNAMIC_SQL: &[DynamicSqlInventory] = &[
    DynamicSqlInventory {
        file: "crates/buzz-push-gateway/src/postgres.rs",
        owner: "apply_migrations_and_grants",
        argument: "AssertSqlSafe(grants)",
        owner_fingerprint: "59f2bddd81022c88a9b0367cde36ec53e07c44a09ad643d0db5f3dd83d5244e0",
    },
    DynamicSqlInventory {
        file: "crates/buzz-db/src/channel.rs",
        owner: "get_accessible_channels",
        argument: "sqlx::AssertSqlSafe(sql)",
        owner_fingerprint: "7af8e9f780718222d78e758c31195886532537b7182169b1a72b6f983d8fb5c9",
    },
    DynamicSqlInventory {
        file: "crates/buzz-db/src/channel.rs",
        owner: "get_users_bulk",
        argument: "sqlx::AssertSqlSafe(sql)",
        owner_fingerprint: "ed904badf2c3b9dfeaf6e0c4fe560753732a1b1fcdd6428c8c4f0d27a19c29cb",
    },
    DynamicSqlInventory {
        file: "crates/buzz-db/src/channel.rs",
        owner: "update_channel",
        argument: "sqlx::AssertSqlSafe(sql)",
        owner_fingerprint: "ec7c073f7e618b4d69c79d093b1c8a8320aeb3c8464f550c96a1c0b33162841f",
    },
    DynamicSqlInventory {
        file: "crates/buzz-db/src/deletion.rs",
        owner: "inventory_schema",
        argument: "AssertSqlSafe(sql)",
        owner_fingerprint: "99d744cf8d197e25ee7b620763e7959923517ea7b6f9b5374a0a1c512b5abafb",
    },
    DynamicSqlInventory {
        file: "crates/buzz-db/src/deletion.rs",
        owner: "purge_postgres",
        argument: "AssertSqlSafe(sql)",
        owner_fingerprint: "5d4334785028afef39f9d2f0c42aafce6052a880aeb02d72cd1f102390f5605c",
    },
    DynamicSqlInventory {
        file: "crates/buzz-db/src/deletion.rs",
        owner: "verify_postgres_logically_deleted",
        argument: "AssertSqlSafe(sql)",
        owner_fingerprint: "1faf00caabcd24464fd6d5a83c3006f9e1b4cdc232dfbe9b66c9efbf7b6e7983",
    },
    DynamicSqlInventory {
        file: "crates/buzz-db/src/partition.rs",
        owner: "ensure_partition",
        argument: "sqlx::AssertSqlSafe(sql)",
        owner_fingerprint: "c2802a7c0fec6293a887befe9f78e4becb76b83b1d7315c1e01496bfb5d3b1ff",
    },
    DynamicSqlInventory {
        file: "crates/buzz-db/src/replica_fence.rs",
        owner: "reader_supports_aurora_identity",
        argument: r#"sqlx::AssertSqlSafe(format!("SELECT {AURORA_IDENTITY_FN}()"))"#,
        owner_fingerprint: "3291240355f9b2901a9ec016a4049bccee71dd89fb4b888c8e95573f9519679e",
    },
    DynamicSqlInventory {
        file: "crates/buzz-db/src/replica_fence.rs",
        owner: "observe_heartbeat",
        argument: "sqlx::AssertSqlSafe(sql)",
        owner_fingerprint: "2f7628e054c9e2a195ed92b01994152150d23ea1a4b87b00e30cdaf99b4d829f",
    },
    DynamicSqlInventory {
        file: "crates/buzz-db/src/thread.rs",
        owner: "get_thread_replies_on",
        argument: "sqlx::AssertSqlSafe(sql)",
        owner_fingerprint: "265ee1d19c2b353857518b25185189993e6ee1b729623890c017aeea2dac2721",
    },
    DynamicSqlInventory {
        file: "crates/buzz-db/src/thread.rs",
        owner: "get_channel_window_on",
        argument: "sqlx::AssertSqlSafe(sql)",
        owner_fingerprint: "084c3d9e3cc3621b8602e7d6a653c8af320152a6bac752d95c57e72fb749e4d4",
    },
    DynamicSqlInventory {
        file: "crates/buzz-db/src/usage.rs",
        owner: "active_user_counts",
        argument: "sqlx::AssertSqlSafe(sql)",
        owner_fingerprint: "2fe366035e0eacd5c071e544d81dab8fdcc220e2904b779ec193b95484122571",
    },
    DynamicSqlInventory {
        file: "crates/buzz-db/src/usage.rs",
        owner: "active_channel_counts",
        argument: "sqlx::AssertSqlSafe(sql)",
        owner_fingerprint: "c812cd6eabca88997c6a46933dfcd45a28360716d1aff35086f7ac02cfbdc94a",
    },
    DynamicSqlInventory {
        file: "crates/buzz-db/src/user.rs",
        owner: "update_user_profile",
        argument: "sqlx::AssertSqlSafe(sql)",
        owner_fingerprint: "2f2be400087028ede8d9281ea5c2b073dbd06f08ef628116f6c3160ddfe3990d",
    },
];

// Exact owners whose QueryBuilder classification cannot be proved from the
// extracted literal fragments alone. Their complete owner source is pinned so
// each exception becomes stale on any edit.
struct QueryBuilderException {
    file: &'static str,
    owner: &'static str,
    owner_fingerprint: &'static str,
}

const QUERY_BUILDER_EXCEPTIONS: &[QueryBuilderException] = &[
    QueryBuilderException {
        file: "crates/buzz-db/src/lib.rs",
        owner: "insert_mentions",
        owner_fingerprint: "c888a340801e900d6511de81c5d63c6f87afa030a87847b9df8b23846904b213",
    },
    QueryBuilderException {
        file: "crates/buzz-db/src/event.rs",
        owner: "query_events_on",
        owner_fingerprint: "f06a482fa31252f376ca6cec4a83e9e2675f052810e5d8bbfe6784a7dd44dc45",
    },
    QueryBuilderException {
        file: "crates/buzz-db/src/event.rs",
        owner: "count_events_on",
        owner_fingerprint: "7f48326ae5789c421653ed85fc612242e9a7b054ec9915cda13b4d294dd107f2",
    },
    QueryBuilderException {
        file: "crates/buzz-db/src/event.rs",
        owner: "get_last_message_at_bulk",
        owner_fingerprint: "a3e9ef0f2eea7df90f052380e85fa7f96cd80ac540969d8ab8319fb135d98312",
    },
    QueryBuilderException {
        file: "crates/buzz-db/src/event.rs",
        owner: "get_events_by_ids_on",
        owner_fingerprint: "6f18d34658052e2437767c7ff8063cf3e28dfc11a5b8a2c001c329dc1114a056",
    },
    QueryBuilderException {
        file: "crates/buzz-db/src/channel.rs",
        owner: "get_member_counts_bulk",
        owner_fingerprint: "877c8e955a81bd28b8477a4967b67e3036ff95be8e7c3e33a4413119b2cc58aa",
    },
    QueryBuilderException {
        file: "crates/buzz-search/src/query.rs",
        owner: "search",
        owner_fingerprint: "ca8adf19af50a6c7310bc2e9d1c7ed7be000677815e9a2fe46af4b158409f189",
    },
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
    let roots = workspace_crates()
        .into_iter()
        .map(|name| repo_root().join("crates").join(name).join("src"))
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    assert!(!roots.is_empty(), "workspace has no production crate roots");
    roots
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

fn all_sqlx_matches(roots: &[PathBuf]) -> Vec<serde_json::Value> {
    ast_matches_for_rule(roots, "scripts/lints/community_sqlx_calls.yml")
}

fn querybuilder_mutations(roots: &[PathBuf]) -> Vec<serde_json::Value> {
    ast_matches_for_rule(roots, "scripts/lints/community_querybuilder_mutations.yml")
}

fn querybuilder_builds(roots: &[PathBuf]) -> Vec<serde_json::Value> {
    ast_matches_for_rule(roots, "scripts/lints/community_querybuilder_builds.yml")
}

fn querybuilder_control_flow(roots: &[PathBuf]) -> Vec<serde_json::Value> {
    ast_matches_for_rule(
        roots,
        "scripts/lints/community_querybuilder_control_flow.yml",
    )
}

fn test_module_ranges(roots: &[PathBuf]) -> BTreeMap<PathBuf, Vec<(u64, u64)>> {
    let mut cfg_offsets = BTreeMap::<PathBuf, Vec<u64>>::new();
    for matched in ast_matches_for_rule(roots, "scripts/lints/community_cfg_test_attributes.yml") {
        let path = PathBuf::from(matched["file"].as_str().expect("cfg(test) file"));
        let offset = matched["range"]["byteOffset"]["start"]
            .as_u64()
            .expect("cfg offset");
        cfg_offsets.entry(path).or_default().push(offset);
    }

    let mut ranges = BTreeMap::<PathBuf, Vec<(u64, u64)>>::new();
    for matched in ast_matches_for_rule(roots, "scripts/lints/community_modules.yml") {
        let path = PathBuf::from(matched["file"].as_str().expect("module file"));
        let start = matched["range"]["byteOffset"]["start"]
            .as_u64()
            .expect("module start");
        let end = matched["range"]["byteOffset"]["end"]
            .as_u64()
            .expect("module end");
        let source = fs::read_to_string(&path).expect("read module source");
        let attributed = cfg_offsets.get(&path).is_some_and(|offsets| {
            offsets.iter().any(|offset| {
                *offset < start
                    && source[*offset as usize..start as usize]
                        .trim()
                        .starts_with("#[cfg(test)]")
            })
        });
        if attributed {
            ranges.entry(path).or_default().push((start, end));
        }
    }
    ranges
}

#[derive(Debug)]
struct FunctionOwner {
    path: PathBuf,
    start: u64,
    end: u64,
    name: String,
    text: String,
}

fn function_owners(roots: &[PathBuf]) -> Vec<FunctionOwner> {
    ast_matches_for_rule(roots, "scripts/lints/community_function_items.yml")
        .into_iter()
        .filter_map(|matched| {
            let text = matched["text"].as_str()?.to_owned();
            let signature = regex_lite::Regex::new(r"(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)")
                .expect("function signature regex");
            let name = signature.captures(&text)?.get(1)?.as_str().to_owned();
            Some(FunctionOwner {
                path: PathBuf::from(matched["file"].as_str()?),
                start: matched["range"]["byteOffset"]["start"].as_u64()?,
                end: matched["range"]["byteOffset"]["end"].as_u64()?,
                name,
                text,
            })
        })
        .collect()
}

fn const_sql_definitions(roots: &[PathBuf]) -> Vec<serde_json::Value> {
    ast_matches_for_rule(roots, "scripts/lints/community_const_sql.yml")
}

fn conditional_sql_definitions(roots: &[PathBuf]) -> Vec<serde_json::Value> {
    ast_matches_for_rule(roots, "scripts/lints/community_conditional_sql.yml")
}

fn normalize_token(token: &str) -> String {
    token
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect()
}

fn source_fingerprint(source: &str) -> String {
    let normalized = source
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    hex::encode(Sha256::digest(normalized))
}

fn dynamic_inventory_matches(
    entry: &DynamicSqlInventory,
    relative: &str,
    owner: &FunctionOwner,
    sql_token: &str,
) -> bool {
    relative == entry.file
        && owner.name == entry.owner
        && normalize_token(sql_token) == normalize_token(entry.argument)
        && source_fingerprint(&owner.text) == entry.owner_fingerprint
}

fn querybuilder_exception_matches(
    entry: &QueryBuilderException,
    relative: &str,
    owner: &FunctionOwner,
) -> bool {
    relative == entry.file
        && owner.name == entry.owner
        && source_fingerprint(&owner.text) == entry.owner_fingerprint
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
            op: BinaryOperator::And,
            right,
        } => {
            predicate_is_directly_gated(Some(left), aliases)
                || predicate_is_directly_gated(Some(right), aliases)
        }
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Or,
            right,
        } => {
            predicate_is_directly_gated(Some(left), aliases)
                && predicate_is_directly_gated(Some(right), aliases)
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
            query_contains_direct_gate(subquery)
        }
        expr => is_allowed_function(expr, aliases),
    }
}

fn select_aliases(select: &Select) -> BTreeSet<String> {
    select
        .from
        .iter()
        .filter_map(|table| {
            table_factor_name(&table.relation)
                .map(|target| target_aliases(&table.relation, &target))
        })
        .flatten()
        .collect()
}

fn select_projection_expr(select: &Select, index: usize) -> Option<&Expr> {
    match select.projection.get(index)? {
        SelectItem::UnnamedExpr(expr)
        | SelectItem::ExprWithAlias { expr, .. }
        | SelectItem::ExprWithAliases { expr, .. } => Some(expr),
        SelectItem::QualifiedWildcard(..) | SelectItem::Wildcard(..) => None,
    }
}

fn query_contains_direct_gate(query: &Query) -> bool {
    match query.body.as_ref() {
        SetExpr::Select(select) => {
            predicate_is_directly_gated(select.selection.as_ref(), &select_aliases(select))
        }
        SetExpr::Query(query) => query_contains_direct_gate(query),
        SetExpr::SetOperation { left, right, .. } => {
            set_expr_contains_direct_gate(left) && set_expr_contains_direct_gate(right)
        }
        _ => false,
    }
}

fn set_expr_contains_direct_gate(set: &SetExpr) -> bool {
    match set {
        SetExpr::Select(select) => {
            predicate_is_directly_gated(select.selection.as_ref(), &select_aliases(select))
        }
        SetExpr::Query(query) => query_contains_direct_gate(query),
        SetExpr::SetOperation { left, right, .. } => {
            set_expr_contains_direct_gate(left) && set_expr_contains_direct_gate(right)
        }
        _ => false,
    }
}

fn select_projected_community_is_safe(select: &Select, index: usize) -> bool {
    let aliases = select_aliases(select);
    let Some(projected) = select_projection_expr(select, index) else {
        return false;
    };
    match projected {
        Expr::Value(value) if matches!(&value.value, Value::Placeholder(_)) => true,
        expr if is_allowed_function(expr, &aliases) => true,
        expr if is_community_column(expr, &aliases) => {
            let projected_alias = match expr {
                Expr::CompoundIdentifier(parts) if parts.len() >= 2 => {
                    BTreeSet::from([parts[parts.len() - 2].value.to_ascii_lowercase()])
                }
                Expr::Identifier(_) if select.from.len() == 1 => aliases,
                _ => return false,
            };
            predicate_is_directly_gated(select.selection.as_ref(), &projected_alias)
        }
        _ => false,
    }
}

fn set_projected_community_is_safe(set: &SetExpr, index: usize) -> bool {
    match set {
        SetExpr::Select(select) => select_projected_community_is_safe(select, index),
        SetExpr::Query(query) => projected_community_is_safe(query, index),
        SetExpr::SetOperation { left, right, .. } => {
            set_projected_community_is_safe(left, index)
                && set_projected_community_is_safe(right, index)
        }
        SetExpr::Values(values) => values.rows.iter().all(|row| {
            row.get(index).is_some_and(|expr| {
                matches!(expr, Expr::Value(value) if matches!(&value.value, Value::Placeholder(_)))
            })
        }),
        _ => false,
    }
}

fn projected_community_is_safe(query: &Query, index: usize) -> bool {
    set_projected_community_is_safe(query.body.as_ref(), index)
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
        Statement::Insert(Insert {
            table,
            columns,
            source,
            ..
        }) => {
            let TableObject::TableName(table_name) = table else {
                return None;
            };
            let target = basename(table_name);
            if !fenced.contains(&target) {
                return None;
            }
            if columns.is_empty() {
                return Some(format!(
                    "INSERT into {target} omits its target column list; community_id provenance is unknown"
                ));
            }
            let Some(community_index) = columns
                .iter()
                .position(|column| basename(column) == "community_id")
            else {
                return Some(format!(
                    "INSERT into {target} omits community_id from its target columns"
                ));
            };
            let Some(source) = source else { return None };
            (!projected_community_is_safe(source, community_index)).then(|| {
                format!(
                    "INSERT into {target} does not prove target community_id is tenant-bound or gated"
                )
            })
        }
        _ => None,
    }
}

fn querybuilder_mutation_statement(statement: &Statement) -> bool {
    matches!(
        statement,
        Statement::Delete(_) | Statement::Update(_) | Statement::Insert(_)
    )
}

fn parsed_querybuilder_is_read_only(statements: &[Statement]) -> bool {
    !statements.is_empty()
        && statements
            .iter()
            .all(|statement| matches!(statement, Statement::Query(_)))
}

fn parse_sql(sql: &str) -> Result<Vec<Statement>, String> {
    Parser::parse_sql(&PostgreSqlDialect {}, sql).map_err(|error| error.to_string())
}

fn inspect_matches(matches: &[serde_json::Value], roots: &[PathBuf]) -> Vec<String> {
    let owners = function_owners(roots);
    inspect_matches_with_owners(matches, roots, &owners)
}

fn inspect_matches_with_owners(
    matches: &[serde_json::Value],
    roots: &[PathBuf],
    owners: &[FunctionOwner],
) -> Vec<String> {
    let fenced = authority();
    let root = repo_root();
    let mut violations = Vec::new();
    let mut observed_parser_exceptions = BTreeSet::new();
    let const_defs = const_sql_definitions(roots);
    let conditional_defs = conditional_sql_definitions(roots);
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
        let sql_token = matched["metaVariables"]["single"]
            .get("SQL")
            .and_then(|sql| sql["text"].as_str());
        if sql_token.is_none() {
            // QueryBuilder execution is validated against its constructor in
            // `querybuilder_executions_have_one_owned_creation` below.
            continue;
        }
        let sql_token = sql_token.expect("checked SQL metavariable");
        let Some(sql) = rust_string_value(sql_token) else {
            let relative = path.strip_prefix(&root).unwrap_or(&path).to_string_lossy();
            let owner = owners
                .iter()
                .find(|owner| owner.path == path && owner.start <= offset && offset < owner.end);
            let dynamic_matches = owner.map_or(0, |owner| {
                DYNAMIC_SQL
                    .iter()
                    .filter(|entry| dynamic_inventory_matches(entry, &relative, owner, sql_token))
                    .count()
            });
            let named_matches = NAMED_SQL
                .iter()
                .filter(|(file, symbol, expression)| {
                    relative == *file
                        && sql_token == *expression
                        && const_defs.iter().any(|definition| {
                            Path::new(definition["file"].as_str().unwrap_or_default()) == path
                                && definition["metaVariables"]["single"]["NAME"]["text"].as_str()
                                    == Some(*symbol)
                        })
                })
                .count();
            let conditional_matches = owner.map_or(0, |owner| {
                CONDITIONAL_SQL
                    .iter()
                    .filter(|(file, expected_owner, expression)| {
                        relative == *file
                            && owner.name == *expected_owner
                            && sql_token == *expression
                            && conditional_defs.iter().any(|definition| {
                                Path::new(definition["file"].as_str().unwrap_or_default()) == path
                                    && definition["range"]["byteOffset"]["start"]
                                        .as_u64()
                                        .is_some_and(|start| {
                                            owner.start <= start && start < owner.end
                                        })
                                    && definition["metaVariables"]["single"]["NAME"]["text"]
                                        .as_str()
                                        == Some(*expression)
                            })
                    })
                    .count()
            });
            let total = dynamic_matches + named_matches + conditional_matches;
            if total != 1 {
                violations.push(format!(
                    "{relative}:{line}: nonliteral SQL expression must match exactly one inventory entry; got {total}: {sql_token}"
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

    for entry in DYNAMIC_SQL {
        let path = root.join(entry.file);
        let count = matches
            .iter()
            .filter(|matched| {
                Path::new(matched["file"].as_str().unwrap_or_default()) == path
                    && matched["metaVariables"]["single"]
                        .get("SQL")
                        .and_then(|sql| sql["text"].as_str())
                        .is_some_and(|token| {
                            owners.iter().any(|owner| {
                                matched["range"]["byteOffset"]["start"]
                                    .as_u64()
                                    .is_some_and(|offset| {
                                        owner.path == path
                                            && owner.start <= offset
                                            && offset < owner.end
                                            && dynamic_inventory_matches(
                                                entry, entry.file, owner, token,
                                            )
                                    })
                            })
                        })
            })
            .count();
        if count != 1 {
            violations.push(format!(
                "{}: dynamic SQL inventory must match exactly once: owner={:?} argument={:?} owner_fingerprint={:?}; got {count}",
                entry.file, entry.owner, entry.argument, entry.owner_fingerprint
            ));
        }
    }
    for (relative, symbol, expression) in NAMED_SQL {
        let path = root.join(relative);
        let definitions = const_defs
            .iter()
            .filter(|definition| {
                Path::new(definition["file"].as_str().unwrap_or_default()) == path
                    && definition["metaVariables"]["single"]["NAME"]["text"].as_str()
                        == Some(*symbol)
            })
            .count();
        let executions = matches
            .iter()
            .filter(|matched| {
                Path::new(matched["file"].as_str().unwrap_or_default()) == path
                    && matched["metaVariables"]["single"]
                        .get("SQL")
                        .and_then(|sql| sql["text"].as_str())
                        == Some(*expression)
            })
            .count();
        if definitions != 1 || executions == 0 {
            violations.push(format!("{relative}: named SQL inventory mismatch for {symbol}: definitions={definitions} executions={executions}"));
        }
    }
    for (relative, expected_owner, expression) in CONDITIONAL_SQL {
        let path = root.join(relative);
        let definitions = conditional_defs
            .iter()
            .filter(|definition| {
                Path::new(definition["file"].as_str().unwrap_or_default()) == path
                    && definition["metaVariables"]["single"]["NAME"]["text"].as_str()
                        == Some(*expression)
                    && definition["range"]["byteOffset"]["start"]
                        .as_u64()
                        .is_some_and(|offset| {
                            owners.iter().any(|owner| {
                                owner.path == path
                                    && owner.name == *expected_owner
                                    && owner.start <= offset
                                    && offset < owner.end
                            })
                        })
            })
            .count();
        if definitions != 1 {
            violations.push(format!("{relative}: conditional SQL inventory mismatch: owner={expected_owner} expression={expression} definitions={definitions}"));
        }
    }
    violations
}

fn querybuilder_violations(roots: &[PathBuf]) -> Vec<String> {
    let production_scan = roots
        .iter()
        .any(|root| root.starts_with(repo_root().join("crates")) && root.ends_with("src"));
    let owners = function_owners(roots);
    let mutations = querybuilder_mutations(roots);
    let builds = querybuilder_builds(roots);
    let control_flow = querybuilder_control_flow(roots);
    let mut found = Vec::new();
    let mut observed_querybuilder_exceptions = BTreeSet::new();
    for build in &builds {
        let path = PathBuf::from(build["file"].as_str().expect("builder file"));
        let offset = build["range"]["byteOffset"]["start"]
            .as_u64()
            .expect("builder offset");
        let owner = owners
            .iter()
            .find(|owner| owner.path == path && owner.start <= offset && offset < owner.end);
        let Some(owner) = owner else {
            continue;
        };
        if !owner.text.contains("QueryBuilder") {
            continue;
        }
        let receiver = build["metaVariables"]["single"]["QB"]["text"]
            .as_str()
            .expect("builder receiver");
        if !receiver
            .chars()
            .all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        {
            found.push(format!(
                "{}: QueryBuilder build has non-identifier receiver {receiver:?}",
                path.display()
            ));
            continue;
        }
        let mut all_owned = mutations
            .iter()
            .filter(|mutation| {
                Path::new(mutation["file"].as_str().unwrap_or_default()) == path
                    && mutation["range"]["byteOffset"]["start"]
                        .as_u64()
                        .is_some_and(|start| owner.start <= start && start < owner.end)
                    && mutation["metaVariables"]["single"]
                        .get("QB")
                        .and_then(|value| value["text"].as_str())
                        == Some(receiver)
            })
            .collect::<Vec<_>>();
        all_owned.sort_by_key(|mutation| {
            mutation["range"]["byteOffset"]["start"]
                .as_u64()
                .unwrap_or_default()
        });
        let constructors = all_owned
            .iter()
            .filter(|mutation| {
                mutation["text"]
                    .as_str()
                    .is_some_and(|text| text.starts_with("let mut "))
            })
            .count();
        if constructors != 1 {
            let relative = path
                .strip_prefix(repo_root())
                .unwrap_or(&path)
                .to_string_lossy();
            let excepted = QUERY_BUILDER_EXCEPTIONS
                .iter()
                .find(|entry| querybuilder_exception_matches(entry, &relative, owner));
            if let Some(entry) = excepted {
                observed_querybuilder_exceptions.insert((entry.file, entry.owner));
            } else {
                found.push(format!("{}: QueryBuilder {receiver} must have exactly one direct constructor in owner {}; got {constructors}", path.display(), owner.name));
            }
            continue;
        }
        if owner.text.contains(&format!("let mut alias = {receiver}"))
            || owner.text.contains(&format!("let alias = {receiver}"))
            || owner.text.contains(&format!("{receiver} =")) && constructors > 1
        {
            found.push(format!(
                "{}: QueryBuilder {receiver} has ambiguous alias/reassignment",
                path.display()
            ));
            continue;
        }
        let constructor_offset = all_owned
            .iter()
            .find(|mutation| {
                mutation["text"]
                    .as_str()
                    .is_some_and(|text| text.starts_with("let mut "))
            })
            .and_then(|mutation| mutation["range"]["byteOffset"]["start"].as_u64())
            .expect("exactly one QueryBuilder constructor");
        if constructor_offset >= offset {
            found.push(format!(
                "{}: QueryBuilder {receiver} constructor does not precede build",
                path.display()
            ));
            continue;
        }
        let fragments = all_owned
            .iter()
            .filter(|mutation| {
                mutation["range"]["byteOffset"]["start"]
                    .as_u64()
                    .is_some_and(|start| constructor_offset <= start && start < offset)
            })
            .filter_map(|mutation| mutation["metaVariables"]["single"].get("SQL")?["text"].as_str())
            .map(|token| rust_string_value(token).ok_or_else(|| token.to_owned()))
            .collect::<Result<Vec<_>, _>>();
        let fragments = match fragments {
            Ok(fragments) => fragments,
            Err(token) => {
                found.push(format!(
                    "{}: QueryBuilder {receiver} has nonliteral fragment {token}",
                    path.display()
                ));
                continue;
            }
        };
        // QueryBuilder appends string fragments exactly, so parse the same
        // byte sequence that will be executed. The AST, not raw keyword
        // spelling, decides whether conditional state is safe to ignore.
        let reconstructed = fragments.concat();
        let relative = path
            .strip_prefix(repo_root())
            .unwrap_or(&path)
            .to_string_lossy();
        let inventory_entry = QUERY_BUILDER_EXCEPTIONS
            .iter()
            .find(|entry| querybuilder_exception_matches(entry, &relative, owner));
        if let Some(entry) = inventory_entry {
            observed_querybuilder_exceptions.insert((entry.file, entry.owner));
        }
        let inventoried = inventory_entry.is_some();
        let parsed = parse_sql(&reconstructed);
        let is_read_only = parsed
            .as_deref()
            .is_ok_and(parsed_querybuilder_is_read_only);
        // Fingerprinted exceptions cover builders whose dynamic bind helpers
        // prevent a complete literal reconstruction, not parsed mutations.
        if is_read_only || (inventoried && parsed.is_err()) {
            continue;
        }
        // Parsed reads and fingerprinted, unparseable exact-owner exceptions
        // are safe to ignore here. Every other shape must pass the conditional-
        // state gate and AST mutation validation below.
        let owner_control_flow = control_flow.iter().filter(|control| {
            Path::new(control["file"].as_str().unwrap_or_default()) == path
                && control["range"]["byteOffset"]["start"]
                    .as_u64()
                    .zip(control["range"]["byteOffset"]["end"].as_u64())
                    .is_some_and(|(start, end)| owner.start <= start && end <= owner.end)
        });
        let mut state_offsets = all_owned
            .iter()
            .filter_map(|mutation| {
                mutation["range"]["byteOffset"]["start"]
                    .as_u64()
                    .filter(|mutation_offset| {
                        constructor_offset <= *mutation_offset && *mutation_offset < offset
                    })
            })
            .collect::<Vec<_>>();
        state_offsets.push(offset);
        let build_state_is_conditional = state_offsets.into_iter().any(|state_offset| {
            owner_control_flow.clone().any(|control| {
                control["range"]["byteOffset"]["start"]
                    .as_u64()
                    .zip(control["range"]["byteOffset"]["end"].as_u64())
                    .is_some_and(|(start, end)| start <= state_offset && state_offset < end)
            })
        });
        if build_state_is_conditional {
            found.push(format!(
                "{}: mutating QueryBuilder {receiver} constructor, mutation, or build is control-flow-dependent",
                path.display()
            ));
            continue;
        }
        let statements = match parsed {
            Ok(statements) if statements.iter().all(querybuilder_mutation_statement) => statements,
            Ok(statements) => {
                found.push(format!(
                    "{}: QueryBuilder {receiver} is neither read-only nor exclusively mutating and has no exact inventory: statements={statements:?}; fragments={fragments:?}",
                    path.display()
                ));
                continue;
            }
            Err(error) => {
                found.push(format!("{}: QueryBuilder {receiver} failed reconstruction and has no exact inventory: {error}; fragments={fragments:?}", path.display()));
                continue;
            }
        };
        let fenced = authority();
        found.extend(statements.iter().filter_map(|statement| {
            mutation_violation(statement, &fenced).map(|violation| {
                format!(
                    "{}: mutating QueryBuilder {receiver}: {violation}",
                    path.display()
                )
            })
        }));
    }
    if production_scan {
        for entry in QUERY_BUILDER_EXCEPTIONS {
            if !observed_querybuilder_exceptions.contains(&(entry.file, entry.owner)) {
                found.push(format!(
                    "{}: QueryBuilder inventory entry for {} is stale or unobserved",
                    entry.file, entry.owner
                ));
            }
        }
    }
    found
}

#[test]
fn scanner_rejects_dynamic_producer_changes_with_the_same_argument_token() {
    const REVIEWED_PRODUCER: &str = r#""UPDATE channels SET {}, updated_at = NOW() WHERE community_id = ${param_idx} AND id = ${channel_param_idx} AND deleted_at IS NULL""#;
    const UNSAFE_PRODUCER: &str = r#""DELETE FROM relay_invites WHERE expires_at < now() /* {} ${param_idx} ${channel_param_idx} */""#;

    let roots = production_roots();
    let matches = ast_matches(&roots);
    let mut owners = function_owners(&roots);
    let entry = DYNAMIC_SQL
        .iter()
        .find(|entry| {
            entry.file == "crates/buzz-db/src/channel.rs" && entry.owner == "update_channel"
        })
        .expect("update_channel dynamic inventory");
    let owner_index = owners
        .iter()
        .position(|owner| owner.path == repo_root().join(entry.file) && owner.name == entry.owner)
        .expect("update_channel owner");
    let source = owners[owner_index].text.clone();
    assert!(
        source.contains(REVIEWED_PRODUCER),
        "reviewed update_channel SQL producer drifted"
    );
    assert!(
        source.contains(entry.argument),
        "calibration requires the inventoried argument token"
    );

    for (description, mutant) in [
        (
            "unsafe SQL producer",
            source.replacen(REVIEWED_PRODUCER, UNSAFE_PRODUCER, 1),
        ),
        (
            "additional dynamic execution in the reviewed owner",
            source.replacen(
                entry.argument,
                &format!(
                    "{}); sqlx::query(sqlx::AssertSqlSafe(attacker_sql",
                    entry.argument
                ),
                1,
            ),
        ),
    ] {
        assert!(
            mutant.contains(entry.argument),
            "{description} mutant changed the inventoried SQL argument token"
        );
        owners[owner_index].text = mutant;
        let violations = inspect_matches_with_owners(&matches, &roots, &owners);
        assert!(
            violations.iter().any(|violation| {
                violation.contains("crates/buzz-db/src/channel.rs")
                    && violation.contains(
                        "nonliteral SQL expression must match exactly one inventory entry",
                    )
                    && violation.contains(entry.argument)
            }),
            "{description} mutant escaped: {violations:?}"
        );
    }
}

#[test]
fn every_workspace_sql_execution_is_scanned_and_querybuilders_are_owned() {
    let roots = production_roots();
    let matches = all_sqlx_matches(&roots);
    assert!(
        !matches.is_empty(),
        "SQL execution coverage probe matched no calls"
    );
    for matched in &matches {
        assert!(
            matched["file"].as_str().is_some(),
            "SQL execution match has no source file"
        );
    }
    let violations = querybuilder_violations(&roots);
    assert!(
        violations.is_empty(),
        "QueryBuilder violations:
{}",
        violations.join(
            "
"
        )
    );
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
    let violations = inspect_matches(&matches, std::slice::from_ref(&fixture));
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
    for (fixture_name, description) in [
        ("bad_or_delete", "OR-broadened DELETE"),
        (
            "bad_insert_unfenced_source",
            "unfenced-source INSERT SELECT",
        ),
        (
            "bad_insert_unrelated_alias",
            "unrelated-alias INSERT SELECT",
        ),
        (
            "bad_dynamic_assert_sql_safe",
            "unreviewed AssertSqlSafe dynamic SQL",
        ),
        (
            "bad_insert_implicit_columns",
            "implicit-column INSERT SELECT",
        ),
        ("bad_generic_query", "generic query constructor"),
        ("bad_query_with", "query_with constructor"),
        ("bad_query_as_with", "query_as_with constructor"),
        ("bad_query_scalar_with", "query_scalar_with constructor"),
        ("bad_raw_sql", "raw_sql constructor"),
        (
            "bad_dynamic_second_in_owner",
            "second dynamic expression in inventoried owner",
        ),
    ] {
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains(fixture_name)),
            "{description} control escaped: {violations:?}"
        );
    }
    let builder_violations = querybuilder_violations(std::slice::from_ref(&fixture));
    for fixture_name in [
        "bad_querybuilder_direct",
        "bad_querybuilder_split",
        "bad_querybuilder_two_receivers",
        "bad_querybuilder_branch",
        "bad_querybuilder_alias",
        "bad_querybuilder_conditional_push",
        "bad_querybuilder_conditional_whitespace",
        "bad_querybuilder_post_build_push",
    ] {
        assert!(
            builder_violations
                .iter()
                .any(|violation| violation.contains(fixture_name)),
            "QueryBuilder control {fixture_name} escaped: {builder_violations:?}"
        );
    }
    assert!(
        builder_violations.iter().any(|violation| {
            violation.contains("bad_querybuilder_conditional_push")
                && violation.contains("control-flow-dependent")
        }),
        "comment-separated conditional DELETE QueryBuilder tenant predicate escaped the control-flow gate: {builder_violations:?}"
    );
    assert!(
        builder_violations
            .iter()
            .filter(|violation| {
                violation.contains("bad_querybuilder_conditional_whitespace")
                    && violation.contains("control-flow-dependent")
            })
            .count()
            == 2,
        "tab-separated UPDATE or newline-separated INSERT QueryBuilder escaped the control-flow gate: {builder_violations:?}"
    );
    assert!(
        !builder_violations
            .iter()
            .any(|violation| violation.contains("good_querybuilder_conditional_select")),
        "conditional SELECT QueryBuilder was rejected: {builder_violations:?}"
    );
    assert!(
        !violations.iter().any(|v| v.contains("good_tenant_delete")),
        "tenant-bound control was rejected: {violations:?}"
    );
    assert!(
        !violations.iter().any(|v| v.contains("good_gated_delete")),
        "gated control was rejected: {violations:?}"
    );
    assert!(
        !violations
            .iter()
            .any(|v| v.contains("good_cfg_test_module")),
        "actual cfg(test) module was treated as production: {violations:?}"
    );
}
