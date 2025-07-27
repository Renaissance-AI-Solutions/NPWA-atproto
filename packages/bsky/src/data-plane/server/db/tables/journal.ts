import { Generated, Selectable } from 'kysely'

export interface Journal {
  uri: string
  cid: string
  creator: string
  text: string
  entryType: 'real_time' | 'backdated'
  incidentTimestamp: string | null
  locationLat: number | null
  locationLng: number | null
  locationAccuracy: number | null
  locationAddress: string | null
  symptoms: string | null // JSON array of symptom objects
  evidenceUris: string | null // JSON array of evidence URIs
  sources: string | null // JSON array of source objects
  tags: string | null // JSON array of tags
  isPrivate: Generated<boolean>
  createdAt: string
  indexedAt: string
}

export type JournalRow = Selectable<Journal>
export type PartialDB = { journal_entry: Journal }

export const tableName = 'journal_entry'

export const ref = (alias?: string) => {
  return alias ? (`${alias}.${tableName}` as const) : tableName
} 