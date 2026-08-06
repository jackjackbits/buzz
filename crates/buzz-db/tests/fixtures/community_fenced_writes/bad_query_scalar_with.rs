fn mutant(sql: String, args: sqlx::postgres::PgArguments) { sqlx::query_scalar_with::<sqlx::Postgres, i32, _>(sqlx::AssertSqlSafe(sql), args); }
