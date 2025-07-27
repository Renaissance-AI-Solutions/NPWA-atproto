import { Generated, Selectable } from 'kysely'

export interface Sources {
  id: string
  name: string
  url: string | null
  documentId: string | null
  badgeType: 'havana' | 'gangstalked' | 'targeted' | 'whistleblower' | 'retaliation' | null
  upvotes: Generated<number>
  downvotes: Generated<number>
  rank: Generated<'new' | 'debated' | 'debunked' | 'slightly_vetted' | 'vetted' | 'trusted'>
  createdAt: string
  updatedAt: string
}

export type SourcesEntry = Selectable<Sources>

export const tableName = 'sources'

export type PartialDB = { [tableName]: Sources }
