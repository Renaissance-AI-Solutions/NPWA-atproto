#!/usr/bin/env node

import { Kysely, sql } from 'kysely'
import { Database as BetterSqlite3Database } from 'better-sqlite3'
import { SqliteDialect } from 'kysely'
import { PostgresDialect } from 'kysely'
import { Pool } from 'pg'
import { seedSources, clearSources } from '../src/db/seed-sources'

async function main() {
  const command = process.argv[2]
  
  if (!command || !['seed', 'clear'].includes(command)) {
    console.log('Usage: node bin/seed-sources.ts [seed|clear]')
    process.exit(1)
  }
  
  // Use environment variables to connect to the dev-infra database
  const db = new Kysely({
    dialect: new PostgresDialect({
      pool: new Pool({
        host: process.env.DB_HOST || 'localhost',
        port: parseInt(process.env.DB_PORT || '5433', 10), // dev-infra uses port 5433
        database: process.env.DB_NAME || 'pds',
        user: process.env.DB_USER || 'postgres',
        password: process.env.DB_PASSWORD || 'password',
        max: 10,
      }),
    }),
  })
  
  try {
    // Test connection
    await sql`SELECT 1`.execute(db)
    console.log('Database connection successful')
    
    if (command === 'seed') {
      await seedSources(db)
    } else if (command === 'clear') {
      await clearSources(db)
    }
    
    console.log('Operation completed successfully')
  } catch (error) {
    console.error('Database operation failed:', error)
    process.exit(1)
  } finally {
    await db.destroy()
  }
}

main().catch(console.error)