fn mutant(dynamic_sql: String) {
    sqlx::raw_sql(sqlx::AssertSqlSafe(dynamic_sql));
}
