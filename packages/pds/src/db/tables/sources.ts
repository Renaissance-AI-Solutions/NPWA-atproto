import { Generated } from 'kysely'

export const sourcesTableName = 'sources'

export interface Sources {
  id: string
  name: string
  url: string | null
  documentId: string | null
  badgeType: 'havana' | 'gangstalked' | 'targeted' | 'whistleblower' | 'retaliation' | null
  upvotes: number
  downvotes: number
  rank: 'new' | 'debated' | 'debunked' | 'slightly_vetted' | 'vetted' | 'trusted'
  createdAt: string
  updatedAt: string
}

export type PartialDB = {
  [sourcesTableName]: Sources
} 