//! Repository-complete structural guard for production writes to community-fenced tables.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use sqlparser::ast::{
    BinaryOperator, Expr, FromTable, FunctionArg, FunctionArgExpr, FunctionArguments, Insert,
    ObjectName, Query, Select, SelectItem, SetExpr, Statement, TableFactor, TableObject, Value,
};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

const AUTHORITY: &[&str] = buzz_db::deletion::EXPECTED_SCOPED_TABLES;
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

const DYNAMIC_SQL: &[(&str, &str, &[&str])] = &[
    (
        "crates/buzz-push-gateway/src/postgres.rs",
        "apply_migrations_and_grants",
        &[
            "REVOKE CREATE ON DATABASE {database}",
            "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE",
        ],
    ),
    (
        "crates/buzz-db/src/channel.rs",
        "get_accessible_channels",
        &["FROM channels c", "WHERE c.community_id = $1"],
    ),
    (
        "crates/buzz-db/src/channel.rs",
        "get_users_bulk",
        &["FROM users WHERE community_id = $1"],
    ),
    (
        "crates/buzz-db/src/channel.rs",
        "update_channel",
        &[
            "UPDATE channels SET {}",
            "WHERE community_id = ${param_idx}",
        ],
    ),
    (
        "crates/buzz-db/src/deletion.rs",
        "inventory_schema",
        &["SELECT count(*)::BIGINT FROM {table} WHERE community_id = $1"],
    ),
    (
        "crates/buzz-db/src/deletion.rs",
        "purge_postgres",
        &["DELETE FROM {table} WHERE community_id = $1"],
    ),
    (
        "crates/buzz-db/src/deletion.rs",
        "verify_postgres_logically_deleted",
        &["SELECT EXISTS(SELECT 1 FROM {table} WHERE community_id = $1 LIMIT 1)"],
    ),
    (
        "crates/buzz-db/src/lib.rs",
        "insert_mentions",
        &[
            "INSERT INTO event_mentions",
            "push_bind(community_id.as_uuid())",
        ],
    ),
    (
        "crates/buzz-db/src/partition.rs",
        "ensure_partition",
        &["CREATE TABLE IF NOT EXISTS {partition_name} PARTITION OF {table_name}"],
    ),
    (
        "crates/buzz-db/src/replica_fence.rs",
        "reader_supports_aurora_identity",
        &["SELECT {AURORA_IDENTITY_FN}()"],
    ),
    (
        "crates/buzz-db/src/replica_fence.rs",
        "observe_heartbeat",
        &["FROM replica_heartbeat WHERE id = 1"],
    ),
    (
        "crates/buzz-db/src/thread.rs",
        "get_thread_replies_on",
        &["WHERE tm.community_id = $1"],
    ),
    (
        "crates/buzz-db/src/thread.rs",
        "get_channel_window_on",
        &["WHERE e.community_id = $1"],
    ),
    (
        "crates/buzz-db/src/usage.rs",
        "active_user_counts",
        &["SELECT", "FROM events e"],
    ),
    (
        "crates/buzz-db/src/usage.rs",
        "active_channel_counts",
        &["SELECT community_id", "FROM events"],
    ),
    (
        "crates/buzz-db/src/user.rs",
        "update_user_profile",
        &["UPDATE users SET {}", "WHERE community_id = ${param_idx}"],
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

fn parse_sql(sql: &str) -> Result<Vec<Statement>, String> {
    Parser::parse_sql(&PostgreSqlDialect {}, sql).map_err(|error| error.to_string())
}

fn inspect_matches(matches: &[serde_json::Value], roots: &[PathBuf]) -> Vec<String> {
    let fenced = authority();
    let root = repo_root();
    let mut violations = Vec::new();
    let mut observed_parser_exceptions = BTreeSet::new();
    let owners = function_owners(roots);
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
            let source_text = fs::read_to_string(&path).unwrap_or_default();
            let owner = owners
                .iter()
                .find(|owner| owner.path == path && owner.start <= offset && offset < owner.end);
            let inventoried = NAMED_SQL_WRITES.iter().any(|(file, symbol, guard)| {
                relative == *file
                    && sql_token.contains(symbol)
                    && source_text.contains(symbol)
                    && source_text.contains(guard)
            }) || owner.is_some_and(|owner| {
                DYNAMIC_SQL.iter().any(|(file, expected_owner, guards)| {
                    relative == *file
                        && owner.name == *expected_owner
                        && sql_token.contains("AssertSqlSafe")
                        && guards.iter().all(|guard| owner.text.contains(guard))
                })
            });
            let conditional = owner.is_some_and(|owner| {
                CONDITIONAL_SQL_WRITES.iter().any(|(file, symbol, guards)| {
                    relative == *file
                        && sql_token == "statement"
                        && owner.text.contains(symbol)
                        && guards.iter().all(|guard| owner.text.contains(guard))
                })
            });
            if !inventoried && !conditional {
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

    for (relative, expected_owner, guards) in DYNAMIC_SQL {
        let path = root.join(relative);
        let matches = owners
            .iter()
            .filter(|owner| {
                owner.path == path
                    && owner.name == *expected_owner
                    && guards.iter().all(|guard| owner.text.contains(guard))
            })
            .count();
        if matches != 1 {
            violations.push(format!(
                "{relative}: dynamic SQL contract must match exactly once: {expected_owner:?} / {guards:?}; got {matches}"
            ));
        }
    }
    for (relative, symbol, guards) in CONDITIONAL_SQL_WRITES {
        let path = root.join(relative);
        let matches = owners
            .iter()
            .filter(|owner| {
                owner.path == path
                    && owner.text.contains(symbol)
                    && guards.iter().all(|guard| owner.text.contains(guard))
            })
            .count();
        if matches != 1 {
            violations.push(format!(
                "{relative}: conditional SQL contract must match exactly once: {symbol:?} / {guards:?}; got {matches}"
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

fn querybuilder_violations(roots: &[PathBuf]) -> Vec<String> {
    let owners = function_owners(roots);
    let mutations = querybuilder_mutations(roots);
    let mut found = Vec::new();
    for build in querybuilder_builds(roots) {
        let path = PathBuf::from(build["file"].as_str().expect("builder file"));
        let offset = build["range"]["byteOffset"]["start"]
            .as_u64()
            .expect("builder offset");
        let owner = owners
            .iter()
            .find(|owner| owner.path == path && owner.start <= offset && offset < owner.end);
        let Some(owner) = owner else { continue };
        if !owner.text.contains("QueryBuilder") {
            continue;
        }
        let receiver = build["metaVariables"]["single"]["QB"]["text"]
            .as_str()
            .expect("builder receiver");
        let fragments = mutations
            .iter()
            .filter(|mutation| {
                path == Path::new(mutation["file"].as_str().unwrap_or_default())
                    && mutation["range"]["byteOffset"]["start"]
                        .as_u64()
                        .is_some_and(|start| owner.start <= start && start < owner.end)
            })
            .filter_map(|mutation| mutation["metaVariables"]["single"].get("SQL")?["text"].as_str())
            .filter_map(rust_string_value)
            .collect::<Vec<_>>();
        if fragments.is_empty() {
            found.push(format!(
                "{}: QueryBuilder {receiver} has no literal fragments",
                path.display()
            ));
            continue;
        }
        let reconstructed = fragments.join(" ");
        if !["insert into", "update ", "delete from"]
            .iter()
            .any(|keyword| reconstructed.to_ascii_lowercase().contains(keyword))
        {
            continue;
        }
        let relative = path
            .strip_prefix(repo_root())
            .unwrap_or(&path)
            .to_string_lossy();
        let statements = match parse_sql(&reconstructed) {
            Ok(statements) => statements,
            Err(error) => {
                let inventoried = DYNAMIC_SQL.iter().any(|(file, expected_owner, guards)| {
                    relative == *file
                        && owner.name == *expected_owner
                        && guards.iter().all(|guard| owner.text.contains(guard))
                });
                if !inventoried {
                    found.push(format!("{}: mutating QueryBuilder {receiver} failed reconstruction and has no exact owner inventory: {error}; fragments={fragments:?}", path.display()));
                }
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
    found
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
    ] {
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains(fixture_name)),
            "{description} control escaped: {violations:?}"
        );
    }
    let builder_violations = querybuilder_violations(std::slice::from_ref(&fixture));
    for fixture_name in ["bad_querybuilder_direct", "bad_querybuilder_split"] {
        assert!(
            builder_violations
                .iter()
                .any(|violation| violation.contains(fixture_name)),
            "QueryBuilder control {fixture_name} escaped: {builder_violations:?}"
        );
    }
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
