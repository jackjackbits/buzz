fn mutant(flag: bool) {
    let mut qb: sqlx::QueryBuilder<sqlx::Postgres> = if flag {
        sqlx::QueryBuilder::new("DELETE FROM relay_invites WHERE community_id=$1")
    } else {
        sqlx::QueryBuilder::new("DELETE FROM relay_invites WHERE expires_at<now()")
    };
    let _ = qb.build();
}
