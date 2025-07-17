import { Generated } from 'kysely'

export const accessLogsTableName = 'access_logs'

export interface AccessLogs {
  id: Generated<number>
  actorDid: string
  documentId: string | null
  action: string
  accessedAt: string
  ipAddress: string | null
  userAgent: string | null
}

export type PartialDB = {
  [accessLogsTableName]: AccessLogs
} 