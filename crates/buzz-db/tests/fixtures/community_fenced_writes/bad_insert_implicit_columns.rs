fn bad_insert_implicit_columns() {
    sqlx::query("INSERT INTO relay_invites SELECT community_id, id, token_hash, 'member', NULL, 0, now(), 'x', now() FROM relay_invites");
}
