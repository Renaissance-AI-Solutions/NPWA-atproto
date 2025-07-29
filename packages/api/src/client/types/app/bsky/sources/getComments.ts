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
import type * as AppBskyActorDefs from '../actor/defs.js'

const is$typed = _is$typed,
  validate = _validate
const id = 'app.bsky.sources.getComments'

export interface QueryParams {
  /** ID of the source to get comments for. */
  sourceId: string
  /** Maximum number of comments to return. */
  limit?: number
  /** Pagination cursor. */
  cursor?: string
}

export type InputSchema = undefined

export interface OutputSchema {
  comments: Comment[]
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

/** A source comment. */
export interface Comment {
  $type?: 'app.bsky.sources.getComments#comment'
  /** Comment ID. */
  id: string
  /** Source ID. */
  sourceId: string
  author: AppBskyActorDefs.ProfileViewBasic
  /** Comment content. */
  content: string
  /** When the comment was created. */
  createdAt: string
}

const hashComment = 'comment'

export function isComment<V>(v: V) {
  return is$typed(v, id, hashComment)
}

export function validateComment<V>(v: V) {
  return validate<Comment & V>(v, id, hashComment)
}
