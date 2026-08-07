fn bad_insert_unrelated_alias() {
    sqlx::query("INSERT INTO relay_invites (community_id, token_hash, expires_at, created_by) SELECT ri.community_id, ri.token_hash, now(), 'x' FROM relay_invites ri, event_tags et WHERE et.community_id = $1");
}
