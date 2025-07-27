import { Generated } from 'kysely'

export const livestreamsTableName = 'livestreams'

export interface Livestreams {
  id: string
  hostDid: string
  title: string | null
  description: string | null
  startedAt: string
  endedAt: string | null
  emergency: boolean
  streamKey: string | null
  viewerCount: number
  createdAt: string
  updatedAt: string
}

export type PartialDB = {
  [livestreamsTableName]: Livestreams
} 