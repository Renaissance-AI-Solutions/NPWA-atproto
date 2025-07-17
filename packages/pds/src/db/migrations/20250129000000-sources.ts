import { Kysely, sql } from 'kysely'

export async function up(db: Kysely<unknown>): Promise<void> {
  // Create sources table
  await db.schema
    .createTable('sources')
    .addColumn('id', 'uuid', (col) => col.primaryKey())
    .addColumn('name', 'text', (col) => col.notNull())
    .addColumn('url', 'text')
    .addColumn('documentId', 'uuid', (col) => col.references('documents.id'))
    .addColumn('badgeType', 'text')
    .addColumn('upvotes', 'integer', (col) => col.defaultTo(0).notNull())
    .addColumn('downvotes', 'integer', (col) => col.defaultTo(0).notNull())
    .addColumn('rank', 'text', (col) => col.defaultTo('new').notNull())
    .addColumn('createdAt', 'timestamp', (col) => col.defaultTo(sql`CURRENT_TIMESTAMP`).notNull())
    .addColumn('updatedAt', 'timestamp', (col) => col.defaultTo(sql`CURRENT_TIMESTAMP`).notNull())
    .execute()

  // Add check constraint to ensure either url or documentId is provided
  await sql`
    ALTER TABLE sources 
    ADD CONSTRAINT sources_url_or_document_check 
    CHECK (url IS NOT NULL OR documentId IS NOT NULL)
  `.execute(db)

  // Add check constraint for rank enum values
  await sql`
    ALTER TABLE sources 
    ADD CONSTRAINT sources_rank_check 
    CHECK (rank IN ('new', 'debated', 'debunked', 'slightly_vetted', 'vetted', 'trusted'))
  `.execute(db)

  // Add check constraint for badgeType enum values
  await sql`
    ALTER TABLE sources 
    ADD CONSTRAINT sources_badge_type_check 
    CHECK (badgeType IS NULL OR badgeType IN ('havana', 'gangstalked', 'targeted', 'whistleblower', 'retaliation'))
  `.execute(db)

  // Create indexes for efficient querying
  await sql`
    CREATE INDEX idx_sources_rank_votes 
    ON sources (rank, upvotes DESC, downvotes ASC)
  `.execute(db)

  await sql`
    CREATE INDEX idx_sources_badge_rank 
    ON sources (badgeType, rank, upvotes DESC)
  `.execute(db)

  await sql`
    CREATE INDEX idx_sources_document_id 
    ON sources (documentId)
  `.execute(db)
}

export async function down(db: Kysely<unknown>): Promise<void> {
  // Drop indexes first
  await sql`DROP INDEX IF EXISTS idx_sources_document_id`.execute(db)
  await sql`DROP INDEX IF EXISTS idx_sources_badge_rank`.execute(db)
  await sql`DROP INDEX IF EXISTS idx_sources_rank_votes`.execute(db)

  // Drop sources table
  await db.schema.dropTable('sources').execute()
} 