fn good_gated_delete() {
    sqlx::query("DELETE FROM relay_invites WHERE expires_at < now() AND community_write_allowed(community_id)");
}
