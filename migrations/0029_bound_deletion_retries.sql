-- Restore the per-stage retry streak needed to bound transient deletion
-- failures. Migration 0028 is already deployed and checksum-pinned, so this
-- schema addition must remain additive.
ALTER TABLE community_deletion_requests
    ADD COLUMN retry_stage TEXT CHECK (retry_stage IS NULL OR retry_stage IN (
        'approved', 'fenced', 'drained', 'bindings_removed',
        'postgres_purged', 'cache_purged', 'logically_verified'
    ));
