fn bad_unrelated_subquery() {
    sqlx::query("DELETE FROM relay_invites WHERE expires_at < now() AND EXISTS (SELECT 1 FROM communities WHERE id=$1)");
}
