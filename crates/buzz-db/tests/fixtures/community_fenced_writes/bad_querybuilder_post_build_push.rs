fn mutant() {
    let mut qb: sqlx::QueryBuilder<sqlx::Postgres> =
        sqlx::QueryBuilder::new("DELETE FROM relay_invites WHERE expires_at < now()");
    let _ = qb.build();
    qb.push(" AND community_id = $1");
}
