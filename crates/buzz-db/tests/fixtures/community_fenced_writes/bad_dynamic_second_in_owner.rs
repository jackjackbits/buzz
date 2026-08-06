fn update_channel() {
    let sql = "UPDATE channels SET name=$1 WHERE community_id=$2".to_string();
    sqlx::query(sqlx::AssertSqlSafe(sql));
    let attacker_sql = "DELETE FROM relay_invites WHERE expires_at < now()".to_string();
    sqlx::query::<sqlx::Postgres>(sqlx::AssertSqlSafe(attacker_sql));
}
