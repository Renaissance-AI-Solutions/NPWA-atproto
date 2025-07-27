import { randomUUID } from 'crypto'
import { Kysely } from 'kysely'

// Mock sources data from frontend for testing
const MOCK_SOURCES = [
  {
    id: randomUUID(),
    name: 'Havana Syndrome Research Paper - NIH',
    url: 'https://www.nih.gov/news-events/news-releases/nih-study-havana-syndrome',
    documentId: null,
    badgeType: 'havana',
    upvotes: 45,
    downvotes: 3,
    rank: 'vetted',
    createdAt: '2024-01-15T10:30:00Z',
    updatedAt: '2024-01-15T10:30:00Z',
  },
  {
    id: randomUUID(),
    name: 'FBI FOIA Document - Gangstalking Investigation',
    url: 'https://vault.fbi.gov/gangstalking',
    documentId: null,
    badgeType: 'gangstalked',
    upvotes: 23,
    downvotes: 8,
    rank: 'slightly_vetted',
    createdAt: '2024-01-14T15:45:00Z',
    updatedAt: '2024-01-14T15:45:00Z',
  },
  {
    id: randomUUID(),
    name: 'NSA Whistleblower Report - Mass Surveillance',
    url: 'https://www.theguardian.com/world/2013/jun/06/nsa-phone-records-verizon-court-order',
    documentId: null,
    badgeType: 'whistleblower',
    upvotes: 156,
    downvotes: 12,
    rank: 'trusted',
    createdAt: '2024-01-13T09:20:00Z',
    updatedAt: '2024-01-13T09:20:00Z',
  },
  {
    id: randomUUID(),
    name: 'Congressional Hearing on Directed Energy Weapons',
    url: 'https://www.congress.gov/hearing/directed-energy-weapons',
    documentId: null,
    badgeType: 'targeted',
    upvotes: 67,
    downvotes: 5,
    rank: 'vetted',
    createdAt: '2024-01-12T14:10:00Z',
    updatedAt: '2024-01-12T14:10:00Z',
  },
  {
    id: randomUUID(),
    name: 'Retaliation Against Federal Employees - OIG Report',
    url: 'https://www.oig.gov/reports/retaliation-federal-employees',
    documentId: null,
    badgeType: 'retaliation',
    upvotes: 34,
    downvotes: 7,
    rank: 'slightly_vetted',
    createdAt: '2024-01-11T11:55:00Z',
    updatedAt: '2024-01-11T11:55:00Z',
  },
  {
    id: randomUUID(),
    name: 'Unverified Social Media Post',
    url: 'https://twitter.com/user/status/123456',
    documentId: null,
    badgeType: null,
    upvotes: 2,
    downvotes: 15,
    rank: 'debunked',
    createdAt: '2024-01-10T16:30:00Z',
    updatedAt: '2024-01-10T16:30:00Z',
  },
]

export async function seedSources(db: Kysely<unknown>): Promise<void> {
  console.log('Seeding sources table with mock data...')
  
  try {
    // Check if sources already exist - simple approach
    const existingCount = await (db as any)
      .selectFrom('sources')
      .select((qb: any) => qb.fn.count('id').as('count'))
      .executeTakeFirst()
    
    if (existingCount && Number(existingCount.count) > 0) {
      console.log(`Sources table already has ${existingCount.count} records. Skipping seed.`)
      return
    }
  } catch (error) {
    console.log('Sources table does not exist yet, proceeding with seed...')
  }
  
  // Insert mock sources
  await (db as any)
    .insertInto('sources')
    .values(MOCK_SOURCES)
    .execute()
  
  console.log(`Successfully seeded ${MOCK_SOURCES.length} sources.`)
}

// Function to clear all sources (for testing)
export async function clearSources(db: Kysely<unknown>): Promise<void> {
  console.log('Clearing all sources...')
  
  // Clear vote tracking first (foreign key constraint)
  await (db as any).deleteFrom('source_votes').execute()
  
  // Clear sources
  await (db as any).deleteFrom('sources').execute()
  
  console.log('Successfully cleared all sources and votes.')
}