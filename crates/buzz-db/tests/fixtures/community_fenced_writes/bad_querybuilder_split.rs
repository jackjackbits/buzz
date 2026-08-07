fn mutant() { let mut qb: sqlx::QueryBuilder<sqlx::Postgres> = sqlx::QueryBuilder::new("DELETE FROM relay_invites WHERE "); qb.push("expires_at < now()"); let _ = qb.build(); }
