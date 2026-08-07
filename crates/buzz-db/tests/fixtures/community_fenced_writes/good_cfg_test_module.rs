#[cfg(test)]
mod postgres_tests {
    fn ignored_test_writer() {
        sqlx::query("DELETE FROM relay_invites WHERE expires_at < now()");
    }
}
