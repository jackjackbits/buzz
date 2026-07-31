//! Thin `buzz-admin deletions` adapter.

pub use buzz_deletion::Command as DeletionsCommand;

/// Delegate to the shared durable deletion engine.
pub async fn run(command: DeletionsCommand) -> anyhow::Result<i32> {
    buzz_deletion::run(command).await
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    #[test]
    fn default_command_does_not_start_a_deletion_worker() {
        let command = crate::Cli::try_parse_from(["buzz-admin", "list-members"]);
        assert!(command.is_ok());
    }
}
