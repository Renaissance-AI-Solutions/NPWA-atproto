import { Generated } from 'kysely'

export const badgeClaimsTableName = 'badge_claims'

export interface BadgeClaims {
  id: string
  did: string
  badgeType: 'havana' | 'gangstalked' | 'targeted' | 'whistleblower' | 'retaliation'
  verificationLevel: number
  evidenceUri: string | null
  createdAt: string
  updatedAt: string
}

export type PartialDB = {
  [badgeClaimsTableName]: BadgeClaims
} 