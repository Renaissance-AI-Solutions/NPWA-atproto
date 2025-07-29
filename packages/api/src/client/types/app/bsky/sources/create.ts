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
import type * as AppBskySourcesList from './list.js'

const is$typed = _is$typed,
  validate = _validate
const id = 'app.bsky.sources.create'

export interface QueryParams {}

export interface InputSchema {
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
}

export interface OutputSchema {
  source: AppBskySourcesList.Source
}

export interface CallOptions {
  signal?: AbortSignal
  headers?: HeadersMap
  qp?: QueryParams
  encoding?: 'application/json'
}

export interface Response {
  success: boolean
  headers: HeadersMap
  data: OutputSchema
}

export class InvalidRequestError extends XRPCError {
  constructor(src: XRPCError) {
    super(src.status, src.error, src.message, src.headers, { cause: src })
  }
}

export class DuplicateSourceError extends XRPCError {
  constructor(src: XRPCError) {
    super(src.status, src.error, src.message, src.headers, { cause: src })
  }
}

export function toKnownErr(e: any) {
  if (e instanceof XRPCError) {
    if (e.error === 'InvalidRequest') return new InvalidRequestError(e)
    if (e.error === 'DuplicateSource') return new DuplicateSourceError(e)
  }

  return e
}
