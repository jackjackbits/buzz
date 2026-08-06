fn bad_insert_select() {
    sqlx::query("INSERT INTO relay_invites (community_id, token_hash, expires_at, created_by) SELECT community_id, token_hash, now(), 'x' FROM relay_invites");
}
