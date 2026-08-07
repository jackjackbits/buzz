fn mutant(sql: String, args: sqlx::postgres::PgArguments) { sqlx::query_as_with::<sqlx::Postgres, (i32,), _>(sqlx::AssertSqlSafe(sql), args); }
