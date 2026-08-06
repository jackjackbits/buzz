mod tests {
    fn production_writer_despite_name() {
        sqlx::query("DELETE FROM relay_invites WHERE expires_at < now()");
    }
}
