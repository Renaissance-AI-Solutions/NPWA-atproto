/**
 * GENERATED CODE - DO NOT MODIFY
 */
import { HeadersMap, XRPCError } from '@atproto/xrpc'
import { type ValidationResult, BlobRef } from '@atproto/lexicon'
import { CID } from 'multiformats/cid'
import { validate as _validate } from '../../../../lexicons'
import {
  type $Typed,
  is$typed as _is$typed,
  type OmitKey,
} from '../../../../util'

const is$typed = _is$typed,
  validate = _validate
const id = 'app.bsky.sources.list'

export interface QueryParams {
  /** Maximum number of sources to return. */
  limit?: number
  /** Pagination cursor. */
  cursor?: string
  /** Filter by badge type. */
  badgeType?:
    | 'havana'
    | 'gangstalked'
    | 'targeted'
    | 'whistleblower'
    | 'retaliation'
    | (string & {})
  /** Filter by source rank. */
  rank?:
    | 'new'
    | 'debated'
    | 'debunked'
    | 'slightly_vetted'
    | 'vetted'
    | 'trusted'
    | (string & {})
  /** Search query for source name or URL. */
  search?: string
}

export type InputSchema = undefined

export interface OutputSchema {
  sources: Source[]
  /** Next page cursor. */
  cursor?: string
}

export interface CallOptions {
  signal?: AbortSignal
  headers?: HeadersMap
}

export interface Response {
  success: boolean
  headers: HeadersMap
  data: OutputSchema
}

export function toKnownErr(e: any) {
  return e
}

/** A source entry. */
export interface Source {
  $type?: 'app.bsky.sources.list#source'
  /** Source ID. */
  id: string
  /** Source name. */
  name: string
  /** Source URL. */
  url?: string
  /** Reference to document if source is a document. */
  documentId?: string
  /** Associated badge type. */
  badgeType?:
    | 'havana'
    | 'gangstalked'
    | 'targeted'
    | 'whistleblower'
    | 'retaliation'
    | (string & {})
  /** Number of upvotes. */
  upvotes: number
  /** Number of downvotes. */
  downvotes: number
  /** Source credibility rank. */
  rank:
    | 'new'
    | 'debated'
    | 'debunked'
    | 'slightly_vetted'
    | 'vetted'
    | 'trusted'
    | (string & {})
  /** When the source was created. */
  createdAt: string
}

const hashSource = 'source'

export function isSource<V>(v: V) {
  return is$typed(v, id, hashSource)
}

export function validateSource<V>(v: V) {
  return validate<Source & V>(v, id, hashSource)
}
