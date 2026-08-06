fn good_tenant_delete() {
    sqlx::query("DELETE FROM relay_invites WHERE community_id=$1 AND expires_at < $2");
}
