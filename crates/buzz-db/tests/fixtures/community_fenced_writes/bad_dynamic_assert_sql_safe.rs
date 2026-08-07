fn bad_dynamic_assert_sql_safe(dynamic_sql: String) {
    sqlx::query(sqlx::AssertSqlSafe(dynamic_sql));
}
