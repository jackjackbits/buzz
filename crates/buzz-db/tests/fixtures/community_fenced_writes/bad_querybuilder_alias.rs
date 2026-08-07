fn mutant() {
    let mut qb: sqlx::QueryBuilder<sqlx::Postgres> = sqlx::QueryBuilder::new("DELETE FROM relay_invites WHERE expires_at<now()");
    let mut alias = qb;
    let _ = alias.build();
}
