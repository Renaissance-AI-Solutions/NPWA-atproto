import { Generated, Selectable } from 'kysely'

export interface SourceVotes {
  id: string
  sourceId: string
  voterDid: string
  voteType: 'up' | 'down'
  createdAt: string
  updatedAt: string
}

export type SourceVotesEntry = Selectable<SourceVotes>

export const tableName = 'source_votes'

export type PartialDB = { [tableName]: SourceVotes }