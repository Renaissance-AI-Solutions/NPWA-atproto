import { Kysely } from 'kysely'

export async function up(db: Kysely<unknown>): Promise<void> {
  // Create sources table
  await db.schema
    .createTable('sources')
    .addColumn('id', 'varchar', (col) => col.primaryKey())
    .addColumn('name', 'varchar', (col) => col.notNull())
    .addColumn('url', 'varchar')
    .addColumn('documentId', 'varchar')
    .addColumn('badgeType', 'varchar')
    .addColumn('upvotes', 'integer', (col) => col.defaultTo(0).notNull())
    .addColumn('downvotes', 'integer', (col) => col.defaultTo(0).notNull())
    .addColumn('rank', 'varchar', (col) => col.defaultTo('new').notNull())
    .addColumn('createdAt', 'varchar', (col) => col.notNull())
    .addColumn('updatedAt', 'varchar', (col) => col.notNull())
    .execute()

  // Create indexes for efficient querying
  await db.schema
    .createIndex('idx_sources_rank_votes')
    .on('sources')
    .columns(['rank', 'upvotes', 'downvotes'])
    .execute()

  await db.schema
    .createIndex('idx_sources_badge_rank')
    .on('sources')
    .columns(['badgeType', 'rank', 'upvotes'])
    .execute()

  await db.schema
    .createIndex('idx_sources_document_id')
    .on('sources')
    .column('documentId')
    .execute()
}

export async function down(db: Kysely<unknown>): Promise<void> {
  // Drop indexes first
  await db.schema.dropIndex('idx_sources_document_id').execute()
  await db.schema.dropIndex('idx_sources_badge_rank').execute()
  await db.schema.dropIndex('idx_sources_rank_votes').execute()

  // Drop sources table
  await db.schema.dropTable('sources').execute()
}
