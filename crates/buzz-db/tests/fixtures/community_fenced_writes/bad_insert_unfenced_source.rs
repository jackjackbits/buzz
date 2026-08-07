fn bad_insert_unfenced_source() {
    sqlx::query("INSERT INTO relay_invites (community_id, token_hash, expires_at, created_by) SELECT id, decode(repeat('00', 32), 'hex'), now(), 'x' FROM communities");
}
