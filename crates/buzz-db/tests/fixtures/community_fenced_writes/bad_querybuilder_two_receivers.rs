fn mutant() {
    let mut safe: sqlx::QueryBuilder<sqlx::Postgres> = sqlx::QueryBuilder::new("DELETE FROM relay_invites WHERE community_id=$1");
    let mut unsafe_q: sqlx::QueryBuilder<sqlx::Postgres> = sqlx::QueryBuilder::new("DELETE FROM relay_invites WHERE expires_at<now()");
    let _ = safe.build();
    let _ = unsafe_q.build();
}
