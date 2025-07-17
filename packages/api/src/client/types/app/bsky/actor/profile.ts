/**
 * GENERATED CODE - DO NOT MODIFY
 */
import { type ValidationResult, BlobRef } from '@atproto/lexicon'
import { CID } from 'multiformats/cid'
import { validate as _validate } from '../../../../lexicons'
import {
  type $Typed,
  is$typed as _is$typed,
  type OmitKey,
} from '../../../../util'
import type * as ComAtprotoLabelDefs from '../../../com/atproto/label/defs.js'
import type * as ComAtprotoRepoStrongRef from '../../../com/atproto/repo/strongRef.js'

const is$typed = _is$typed,
  validate = _validate
const id = 'app.bsky.actor.profile'

export interface Record {
  $type: 'app.bsky.actor.profile'
  displayName?: string
  /** Free-form profile description text. */
  description?: string
  /** Small image to be displayed next to posts from account. AKA, 'profile picture' */
  avatar?: BlobRef
  /** Larger horizontal image to display behind profile view. */
  banner?: BlobRef
  labels?: $Typed<ComAtprotoLabelDefs.SelfLabels> | { $type: string }
  joinedViaStarterPack?: ComAtprotoRepoStrongRef.Main
  pinnedPost?: ComAtprotoRepoStrongRef.Main
  /** Victim classification badges for targeted individuals. */
  badges?: VictimBadge[]
  createdAt?: string
  [k: string]: unknown
}

const hashRecord = 'main'

export function isRecord<V>(v: V) {
  return is$typed(v, id, hashRecord)
}

export function validateRecord<V>(v: V) {
  return validate<Record & V>(v, id, hashRecord, true)
}

/** A victim classification badge with verification level. */
export interface VictimBadge {
  $type?: 'app.bsky.actor.profile#victimBadge'
  /** Type of victimization being claimed. */
  badgeType:
    | 'havana'
    | 'gangstalked'
    | 'targeted'
    | 'whistleblower'
    | 'retaliation'
    | (string & {})
  /** Verification level: 0=unverified, 1=community, 2=document, 3=ai */
  verificationLevel: number
  /** URI pointing to encrypted evidence blob. */
  evidenceUri?: string
  /** When the badge was verified. */
  verifiedAt?: string
}

const hashVictimBadge = 'victimBadge'

export function isVictimBadge<V>(v: V) {
  return is$typed(v, id, hashVictimBadge)
}

export function validateVictimBadge<V>(v: V) {
  return validate<VictimBadge & V>(v, id, hashVictimBadge)
}
