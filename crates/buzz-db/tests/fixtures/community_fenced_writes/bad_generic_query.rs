fn mutant(dynamic_sql: String) {
    sqlx::query::<sqlx::Postgres>(sqlx::AssertSqlSafe(dynamic_sql));
}
