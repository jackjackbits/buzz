fn mutant(dynamic_sql: String, args: sqlx::postgres::PgArguments) {
    sqlx::query_with(sqlx::AssertSqlSafe(dynamic_sql), args);
}
