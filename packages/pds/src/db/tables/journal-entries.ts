import { Generated } from 'kysely'

export const journalEntriesTableName = 'journal_entries'

export interface JournalEntries {
  uri: string
  did: string
  createdAt: string
  entryType: 'real_time' | 'backdated'
  locationLat: number | null
  locationLng: number | null
  symptoms: string | null
  evidenceUris: string | null
  sourceIds: string | null
  indexedAt: string
}

export type PartialDB = {
  [journalEntriesTableName]: JournalEntries
} 