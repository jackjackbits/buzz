fn control(filter_by_kind: bool) {
    let mut qb: sqlx::QueryBuilder<sqlx::Postgres> =
        sqlx::QueryBuilder::new("SELECT id FROM events WHERE community_id = $1");
    if filter_by_kind {
        qb.push(" AND kind = $2");
    }
    let _ = qb.build();
}
