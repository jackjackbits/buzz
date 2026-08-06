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

fn conditional_delete_cte(scope_to_tenant: bool) {
    let mut qb: sqlx::QueryBuilder<sqlx::Postgres> =
        sqlx::QueryBuilder::new("WITH gone AS (DELETE FROM relay_invites");
    if scope_to_tenant {
        qb.push(" WHERE community_id = $1");
    }
    qb.push(" RETURNING 1) SELECT 1");
    let _ = qb.build();
}

fn conditional_update_cte(scope_to_tenant: bool) {
    let mut qb: sqlx::QueryBuilder<sqlx::Postgres> = sqlx::QueryBuilder::new(
        "WITH changed AS (UPDATE relay_invites SET expires_at = now()",
    );
    if scope_to_tenant {
        qb.push(" WHERE community_id = $1");
    }
    qb.push(" RETURNING 1) SELECT 1");
    let _ = qb.build();
}

fn conditional_insert_cte(scope_to_tenant: bool) {
    let mut qb: sqlx::QueryBuilder<sqlx::Postgres> = sqlx::QueryBuilder::new(
        "WITH made AS (INSERT INTO relay_invites (community_id, token_hash)",
    );
    if scope_to_tenant {
        qb.push(" VALUES ($1, $2)");
    }
    qb.push(" RETURNING 1) SELECT 1");
    let _ = qb.build();
}
