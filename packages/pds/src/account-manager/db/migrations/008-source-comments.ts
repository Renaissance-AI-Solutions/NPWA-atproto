import { Kysely } from 'kysely'

export async function up(db: Kysely<unknown>): Promise<void> {
  await db.schema
    .createTable('source_comments')
    .addColumn('id', 'uuid', (col) => col.primaryKey())
    .addColumn('sourceId', 'uuid', (col) => col.notNull())
    .addColumn('authorDid', 'varchar', (col) => col.notNull())
    .addColumn('content', 'text', (col) => col.notNull())
    .addColumn('createdAt', 'varchar', (col) => col.notNull())
    .addColumn('updatedAt', 'varchar', (col) => col.notNull())
    .execute()

  // Add foreign key constraint to sources table
  await db.schema
    .createIndex('source_comments_sourceId_idx')
    .on('source_comments')
    .column('sourceId')
    .execute()

  // Add index for efficient comment retrieval
  await db.schema
    .createIndex('source_comments_createdAt_idx')
    .on('source_comments')
    .column('createdAt')
    .execute()

  // Add index for author lookups
  await db.schema
    .createIndex('source_comments_authorDid_idx')
    .on('source_comments')
    .column('authorDid')
    .execute()
}

export async function down(db: Kysely<unknown>): Promise<void> {
  await db.schema.dropTable('source_comments').execute()
}