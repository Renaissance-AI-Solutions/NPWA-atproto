import { Generated } from 'kysely'

export const usersTableName = 'users'

export interface Users {
  did: string
  handle: string | null
  role: 'user' | 'moderator' | 'admin'
  createdAt: string
  updatedAt: string
}

export type PartialDB = {
  [usersTableName]: Users
} 