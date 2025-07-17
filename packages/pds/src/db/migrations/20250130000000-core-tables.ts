import { Kysely, sql } from 'kysely'

export async function up(db: Kysely<unknown>): Promise<void> {
  // Create users table (extends account functionality)
  await db.schema
    .createTable('users')
    .addColumn('did', 'text', (col) => col.primaryKey())
    .addColumn('handle', 'text', (col) => col.unique())
    .addColumn('role', 'text', (col) => col.defaultTo('user').notNull())
    .addColumn('createdAt', 'timestamp', (col) => col.defaultTo(sql`CURRENT_TIMESTAMP`).notNull())
    .addColumn('updatedAt', 'timestamp', (col) => col.defaultTo(sql`CURRENT_TIMESTAMP`).notNull())
    .execute()

  // Add role check constraint
  await sql`
    ALTER TABLE users 
    ADD CONSTRAINT users_role_check 
    CHECK (role IN ('user', 'moderator', 'admin'))
  `.execute(db)

  // Create badge_claims table
  await db.schema
    .createTable('badge_claims')
    .addColumn('id', 'uuid', (col) => col.primaryKey())
    .addColumn('did', 'text', (col) => col.notNull().references('users.did'))
    .addColumn('badgeType', 'text', (col) => col.notNull())
    .addColumn('verificationLevel', 'integer', (col) => col.defaultTo(0).notNull())
    .addColumn('evidenceUri', 'text')
    .addColumn('createdAt', 'timestamp', (col) => col.defaultTo(sql`CURRENT_TIMESTAMP`).notNull())
    .addColumn('updatedAt', 'timestamp', (col) => col.defaultTo(sql`CURRENT_TIMESTAMP`).notNull())
    .execute()

  // Add badge_type check constraint
  await sql`
    ALTER TABLE badge_claims 
    ADD CONSTRAINT badge_claims_badge_type_check 
    CHECK (badgeType IN ('havana', 'gangstalked', 'targeted', 'whistleblower', 'retaliation'))
  `.execute(db)

  // Add verification_level check constraint (0=unverified, 1=community, 2=document, 3=ai)
  await sql`
    ALTER TABLE badge_claims 
    ADD CONSTRAINT badge_claims_verification_level_check 
    CHECK (verificationLevel >= 0 AND verificationLevel <= 3)
  `.execute(db)

  // Create documents table
  await db.schema
    .createTable('documents')
    .addColumn('id', 'uuid', (col) => col.primaryKey())
    .addColumn('ownerDid', 'text', (col) => col.notNull().references('users.did'))
    .addColumn('category', 'text', (col) => col.notNull())
    .addColumn('isPhi', 'boolean', (col) => col.defaultTo(false).notNull())
    .addColumn('encryptedUri', 'text', (col) => col.notNull())
    .addColumn('filename', 'text')
    .addColumn('mimeType', 'text')
    .addColumn('size', 'integer')
    .addColumn('createdAt', 'timestamp', (col) => col.defaultTo(sql`CURRENT_TIMESTAMP`).notNull())
    .addColumn('updatedAt', 'timestamp', (col) => col.defaultTo(sql`CURRENT_TIMESTAMP`).notNull())
    .execute()

  // Add category check constraint
  await sql`
    ALTER TABLE documents 
    ADD CONSTRAINT documents_category_check 
    CHECK (category IN ('foia', 'law_enforcement', 'medical', 'legal_other'))
  `.execute(db)

  // Create journal_entries table (critical missing table)
  await db.schema
    .createTable('journal_entries')
    .addColumn('uri', 'text', (col) => col.primaryKey())
    .addColumn('did', 'text', (col) => col.notNull().references('users.did'))
    .addColumn('createdAt', 'timestamp', (col) => col.defaultTo(sql`CURRENT_TIMESTAMP`).notNull())
    .addColumn('entryType', 'text', (col) => col.notNull())
    .addColumn('locationLat', 'real')
    .addColumn('locationLng', 'real')
    .addColumn('symptoms', 'text') // JSON data
    .addColumn('evidenceUris', 'text') // JSON array
    .addColumn('sourceIds', 'text') // JSON array of UUIDs
    .addColumn('indexedAt', 'timestamp', (col) => col.defaultTo(sql`CURRENT_TIMESTAMP`).notNull())
    .execute()

  // Add entry_type check constraint
  await sql`
    ALTER TABLE journal_entries 
    ADD CONSTRAINT journal_entries_entry_type_check 
    CHECK (entryType IN ('real_time', 'backdated'))
  `.execute(db)

  // Create access_logs table for HIPAA compliance
  await db.schema
    .createTable('access_logs')
    .addColumn('id', 'bigserial', (col) => col.primaryKey())
    .addColumn('actorDid', 'text', (col) => col.notNull())
    .addColumn('documentId', 'uuid', (col) => col.references('documents.id'))
    .addColumn('action', 'text', (col) => col.notNull())
    .addColumn('accessedAt', 'timestamp', (col) => col.defaultTo(sql`CURRENT_TIMESTAMP`).notNull())
    .addColumn('ipAddress', 'text')
    .addColumn('userAgent', 'text')
    .execute()

  // Create ai_analysis table
  await db.schema
    .createTable('ai_analysis')
    .addColumn('id', 'bigserial', (col) => col.primaryKey())
    .addColumn('sourceUri', 'text', (col) => col.notNull())
    .addColumn('classifier', 'text', (col) => col.notNull())
    .addColumn('label', 'text', (col) => col.notNull())
    .addColumn('score', 'real', (col) => col.notNull())
    .addColumn('analysisData', 'text') // JSON data
    .addColumn('createdAt', 'timestamp', (col) => col.defaultTo(sql`CURRENT_TIMESTAMP`).notNull())
    .execute()

  // Create livestreams table
  await db.schema
    .createTable('livestreams')
    .addColumn('id', 'uuid', (col) => col.primaryKey())
    .addColumn('hostDid', 'text', (col) => col.notNull().references('users.did'))
    .addColumn('title', 'text')
    .addColumn('description', 'text')
    .addColumn('startedAt', 'timestamp', (col) => col.defaultTo(sql`CURRENT_TIMESTAMP`).notNull())
    .addColumn('endedAt', 'timestamp')
    .addColumn('emergency', 'boolean', (col) => col.defaultTo(false).notNull())
    .addColumn('streamKey', 'text')
    .addColumn('viewerCount', 'integer', (col) => col.defaultTo(0).notNull())
    .addColumn('createdAt', 'timestamp', (col) => col.defaultTo(sql`CURRENT_TIMESTAMP`).notNull())
    .addColumn('updatedAt', 'timestamp', (col) => col.defaultTo(sql`CURRENT_TIMESTAMP`).notNull())
    .execute()

  // Create indexes for performance optimization
  
  // Users indexes
  await sql`CREATE INDEX idx_users_handle ON users(handle)`.execute(db)
  await sql`CREATE INDEX idx_users_role ON users(role)`.execute(db)

  // Badge claims indexes
  await sql`CREATE INDEX idx_badge_claims_did ON badge_claims(did)`.execute(db)
  await sql`CREATE INDEX idx_badge_claims_badge_type ON badge_claims(badgeType)`.execute(db)
  await sql`CREATE INDEX idx_badge_claims_verification_level ON badge_claims(verificationLevel)`.execute(db)

  // Journal entries indexes
  await sql`CREATE INDEX idx_journal_entries_did ON journal_entries(did)`.execute(db)
  await sql`CREATE INDEX idx_journal_entries_created_at ON journal_entries(createdAt)`.execute(db)
  await sql`CREATE INDEX idx_journal_entries_entry_type ON journal_entries(entryType)`.execute(db)
  await sql`CREATE INDEX idx_journal_entries_source_ids ON journal_entries(sourceIds)`.execute(db)

  // Documents indexes
  await sql`CREATE INDEX idx_documents_owner_did ON documents(ownerDid)`.execute(db)
  await sql`CREATE INDEX idx_documents_category ON documents(category)`.execute(db)
  await sql`CREATE INDEX idx_documents_is_phi ON documents(isPhi)`.execute(db)

  // Access logs indexes
  await sql`CREATE INDEX idx_access_logs_actor_did ON access_logs(actorDid)`.execute(db)
  await sql`CREATE INDEX idx_access_logs_document_id ON access_logs(documentId)`.execute(db)
  await sql`CREATE INDEX idx_access_logs_accessed_at ON access_logs(accessedAt)`.execute(db)

  // AI analysis indexes
  await sql`CREATE INDEX idx_ai_analysis_source_uri ON ai_analysis(sourceUri)`.execute(db)
  await sql`CREATE INDEX idx_ai_analysis_classifier ON ai_analysis(classifier)`.execute(db)
  await sql`CREATE INDEX idx_ai_analysis_label ON ai_analysis(label)`.execute(db)

  // Livestreams indexes
  await sql`CREATE INDEX idx_livestreams_host_did ON livestreams(hostDid)`.execute(db)
  await sql`CREATE INDEX idx_livestreams_started_at ON livestreams(startedAt)`.execute(db)
  await sql`CREATE INDEX idx_livestreams_emergency ON livestreams(emergency)`.execute(db)
  await sql`CREATE INDEX idx_livestreams_ended_at ON livestreams(endedAt)`.execute(db)
}

export async function down(db: Kysely<unknown>): Promise<void> {
  // Drop indexes first
  await sql`DROP INDEX IF EXISTS idx_livestreams_ended_at`.execute(db)
  await sql`DROP INDEX IF EXISTS idx_livestreams_emergency`.execute(db)
  await sql`DROP INDEX IF EXISTS idx_livestreams_started_at`.execute(db)
  await sql`DROP INDEX IF EXISTS idx_livestreams_host_did`.execute(db)
  await sql`DROP INDEX IF EXISTS idx_ai_analysis_label`.execute(db)
  await sql`DROP INDEX IF EXISTS idx_ai_analysis_classifier`.execute(db)
  await sql`DROP INDEX IF EXISTS idx_ai_analysis_source_uri`.execute(db)
  await sql`DROP INDEX IF EXISTS idx_access_logs_accessed_at`.execute(db)
  await sql`DROP INDEX IF EXISTS idx_access_logs_document_id`.execute(db)
  await sql`DROP INDEX IF EXISTS idx_access_logs_actor_did`.execute(db)
  await sql`DROP INDEX IF EXISTS idx_documents_is_phi`.execute(db)
  await sql`DROP INDEX IF EXISTS idx_documents_category`.execute(db)
  await sql`DROP INDEX IF EXISTS idx_documents_owner_did`.execute(db)
  await sql`DROP INDEX IF EXISTS idx_journal_entries_source_ids`.execute(db)
  await sql`DROP INDEX IF EXISTS idx_journal_entries_entry_type`.execute(db)
  await sql`DROP INDEX IF EXISTS idx_journal_entries_created_at`.execute(db)
  await sql`DROP INDEX IF EXISTS idx_journal_entries_did`.execute(db)
  await sql`DROP INDEX IF EXISTS idx_badge_claims_verification_level`.execute(db)
  await sql`DROP INDEX IF EXISTS idx_badge_claims_badge_type`.execute(db)
  await sql`DROP INDEX IF EXISTS idx_badge_claims_did`.execute(db)
  await sql`DROP INDEX IF EXISTS idx_users_role`.execute(db)
  await sql`DROP INDEX IF EXISTS idx_users_handle`.execute(db)

  // Drop tables in reverse order of creation
  await db.schema.dropTable('livestreams').execute()
  await db.schema.dropTable('ai_analysis').execute()
  await db.schema.dropTable('access_logs').execute()
  await db.schema.dropTable('journal_entries').execute()
  await db.schema.dropTable('documents').execute()
  await db.schema.dropTable('badge_claims').execute()
  await db.schema.dropTable('users').execute()
} 