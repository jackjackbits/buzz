fn bad_or_delete() {
    sqlx::query("DELETE FROM relay_invites WHERE community_id = $1 OR expires_at < now()");
}
