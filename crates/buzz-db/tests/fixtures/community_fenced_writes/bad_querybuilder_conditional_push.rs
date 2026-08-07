fn mutant(scope_to_tenant: bool) {
    let mut qb: sqlx::QueryBuilder<sqlx::Postgres> =
        sqlx::QueryBuilder::new("DELETE/**/FROM relay_invites");
    if scope_to_tenant {
        qb.push(" WHERE community_id = $1");
    }
    let _ = qb.build();
}
