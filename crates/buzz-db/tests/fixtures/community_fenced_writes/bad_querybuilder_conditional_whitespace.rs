fn tab_separated_update(scope_to_tenant: bool) {
    let mut qb: sqlx::QueryBuilder<sqlx::Postgres> =
        sqlx::QueryBuilder::new("UPDATE\trelay_invites SET expires_at = now()");
    if scope_to_tenant {
        qb.push(" WHERE community_id = $1");
    }
    let _ = qb.build();
}

fn newline_separated_insert(scope_to_tenant: bool) {
    let mut qb: sqlx::QueryBuilder<sqlx::Postgres> = sqlx::QueryBuilder::new(
        "INSERT\nINTO relay_invites (community_id, token_hash) VALUES ($1, $2)",
    );
    if scope_to_tenant {
        qb.push(" ON CONFLICT DO NOTHING");
    }
    let _ = qb.build();
}
