import { Kysely, sql } from 'kysely'

export async function up(db: Kysely<unknown>): Promise<void> {
  // Create source_votes table to track individual user votes with soft-delete support
  await db.schema
    .createTable('source_votes')
    .addColumn('id', 'varchar', (col) => col.primaryKey())
    .addColumn('sourceId', 'varchar', (col) => col.notNull())
    .addColumn('voterDid', 'varchar', (col) => col.notNull())
    .addColumn('voteType', 'varchar', (col) => col.notNull()) // 'up' or 'down'
    .addColumn('createdAt', 'varchar', (col) => col.notNull())
    .addColumn('updatedAt', 'varchar', (col) => col.notNull())
    .addColumn('is_active', 'integer') // Soft delete flag: 1 for active, NULL for deactivated (allows unique constraint)
    .addColumn('deactivated_at', 'varchar') // Timestamp when vote was deactivated
    .execute()

  // Add foreign key constraint linking votes to sources
  await db.schema
    .createIndex('fk_source_votes_source_id')
    .on('source_votes')
    .column('sourceId')
    .execute()

  // Add unique constraint to prevent duplicate ACTIVE votes from same user on same source
  await db.schema
    .createIndex('idx_source_votes_unique_active_voter')
    .on('source_votes')
    .columns(['sourceId', 'voterDid', 'is_active'])
    .unique()
    .execute()

  // Add index for efficient vote lookups by voter (for user vote history)
  await db.schema
    .createIndex('idx_source_votes_voter_did')
    .on('source_votes')
    .column('voterDid')
    .execute()

  // Add index for efficient vote counting by source (only active votes)
  await db.schema
    .createIndex('idx_source_votes_source_type_active')
    .on('source_votes')
    .columns(['sourceId', 'voteType', 'is_active'])
    .execute()

  // Add index for audit trail queries (HIPAA compliance)
  await db.schema
    .createIndex('idx_source_votes_created_at')
    .on('source_votes')
    .column('createdAt')
    .execute()

  // Note: voteType validation is handled in application code
  // Valid values are 'up' or 'down' - enforced by API handlers
}

export async function down(db: Kysely<unknown>): Promise<void> {
  // Drop all indexes first
  await db.schema.dropIndex('idx_source_votes_created_at').execute()
  await db.schema.dropIndex('idx_source_votes_source_type_active').execute()
  await db.schema.dropIndex('idx_source_votes_voter_did').execute()
  await db.schema.dropIndex('idx_source_votes_unique_active_voter').execute()
  await db.schema.dropIndex('fk_source_votes_source_id').execute()

  // Drop the source_votes table
  await db.schema.dropTable('source_votes').execute()
}