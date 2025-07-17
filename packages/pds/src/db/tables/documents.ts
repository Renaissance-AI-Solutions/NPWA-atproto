import { Generated } from 'kysely'

export const documentsTableName = 'documents'

export interface Documents {
  id: string
  ownerDid: string
  category: 'foia' | 'law_enforcement' | 'medical' | 'legal_other'
  isPhi: boolean
  encryptedUri: string
  filename: string | null
  mimeType: string | null
  size: number | null
  createdAt: string
  updatedAt: string
}

export type PartialDB = {
  [documentsTableName]: Documents
} 