fn unconditional_delete_cte() {
    let mut qb: sqlx::QueryBuilder<sqlx::Postgres> = sqlx::QueryBuilder::new(
        "WITH gone AS (DELETE FROM relay_invites RETURNING 1) SELECT 1",
    );
    let _ = qb.build();
}

fn unconditional_update_cte() {
    let mut qb: sqlx::QueryBuilder<sqlx::Postgres> = sqlx::QueryBuilder::new(
        "WITH changed AS (UPDATE relay_invites SET expires_at = now() RETURNING 1) SELECT 1",
    );
    let _ = qb.build();
}

fn unconditional_insert_cte() {
    let mut qb: sqlx::QueryBuilder<sqlx::Postgres> = sqlx::QueryBuilder::new(
        "WITH made AS (INSERT INTO relay_invites (token_hash) VALUES ($1) RETURNING 1) SELECT 1",
    );
    let _ = qb.build();
}

fn nested_unconditional_delete_cte() {
    let mut qb: sqlx::QueryBuilder<sqlx::Postgres> = sqlx::QueryBuilder::new(
        "WITH outer_cte AS (WITH gone AS (DELETE FROM relay_invites RETURNING 1) SELECT 1) SELECT 1",
    );
    let _ = qb.build();
}
