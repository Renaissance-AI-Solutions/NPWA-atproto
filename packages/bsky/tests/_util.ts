import { Server } from 'node:http'
import { AddressInfo } from 'node:net'
import { type Express } from 'express'
import { CID } from 'multiformats/cid'
import { AppBskyFeedGetPostThread } from '@atproto/api'
import { lexToJson } from '@atproto/lexicon'
import { AtUri } from '@atproto/syntax'
import {
  isView as isEmbedRecordView,
  isViewRecord,
} from '../src/lexicon/types/app/bsky/embed/record'
import { isView as isEmbedRecordWithMediaView } from '../src/lexicon/types/app/bsky/embed/recordWithMedia'
import {
  FeedViewPost,
  PostView,
  isPostView,
  isReasonRepost,
  isThreadViewPost,
} from '../src/lexicon/types/app/bsky/feed/defs'
import {
  LabelerView,
  isLabelerView,
  isLabelerViewDetailed,
} from '../src/lexicon/types/app/bsky/labeler/defs'
import { $Typed } from '../src/lexicon/util'

type ThreadViewPost = Extract<
  AppBskyFeedGetPostThread.OutputSchema['thread'],
  { post: { uri: string } }
>

export function assertIsThreadViewPost(
  value: unknown,
): asserts value is ThreadViewPost {
  expect(value).toMatchObject({
    $type: 'app.bsky.feed.defs#threadViewPost',
  })
}

// Swap out identifiers and dates with stable
// values for the purpose of snapshot testing
export const forSnapshot = (obj: unknown) => {
  const records = { [kTake]: 'record' }
  const collections = { [kTake]: 'collection' }
  const users = { [kTake]: 'user' }
  const cids = { [kTake]: 'cids' }
  const unknown = { [kTake]: 'unknown' }
  const toWalk = lexToJson(obj as any) // remove any blobrefs/cids
  return mapLeafValues(toWalk, (item) => {
    const asCid = CID.asCID(item)
    if (asCid !== null) {
      return take(cids, asCid.toString())
    }
    if (typeof item !== 'string') {
      return item
    }
    const str = item.startsWith('did:plc:') ? `at://${item}` : item
    if (str.startsWith('at://')) {
      const uri = new AtUri(str)
      if (uri.rkey) {
        return take(records, str)
      }
      if (uri.collection) {
        return take(collections, str)
      }
      if (uri.hostname) {
        return take(users, str)
      }
      return take(unknown, str)
    }
    if (str.match(/^\d{4}-\d{2}-\d{2}T/)) {
      if (str.match(/\d{6}Z$/)) {
        return constantDate.replace('Z', '000Z') // e.g. microseconds in record createdAt
      } else if (str.endsWith('+00:00')) {
        return constantDate.replace('Z', '+00:00') // e.g. timezone in record createdAt
      } else {
        return constantDate
      }
    }
    if (str.match(/^\d+__bafy/)) {
      return constantKeysetCursor
    }
    if (str.match(/\/img\/[^/]+\/.+\/did:plc:[^/]+\/[^/]+@[\w]+$/)) {
      // Match image urls
      const match = str.match(
        /\/img\/[^/]+\/.+\/(did:plc:[^/]+)\/([^/]+)@[\w]+$/,
      )
      if (!match) return str
      const [, did, cid] = match
      return str.replace(did, take(users, did)).replace(cid, take(cids, cid))
    }
    if (str.match(/\/vid\/did%3Aplc%3A[^/]+\/[^/]+\/[^/]+$/)) {
      // Match video urls
      const match = str.match(/\/vid\/(did%3Aplc%3A[^/]+)\/([^/]+)\/[^/]+$/)
      if (!match) return str
      const [, did, cid] = match
      return str
        .replace(did, take(users, decodeURIComponent(did)))
        .replace(cid, take(cids, cid))
    }
    let isCid: boolean
    try {
      CID.parse(str)
      isCid = true
    } catch (_err) {
      isCid = false
    }
    if (isCid) {
      return take(cids, str)
    }
    return item
  })
}

// Feed testing utils

export const getOriginator = (item: FeedViewPost) => {
  if (isReasonRepost(item.reason)) {
    return item.reason.by.did
  } else {
    return item.post.author.did
  }
}

// Useful for remapping ids in snapshot testing, to make snapshots deterministic.
// E.g. you may use this to map this:
//   [{ uri: 'did://rad'}, { uri: 'did://bad' }, { uri: 'did://rad'}]
// to this:
//   [{ uri: '0'}, { uri: '1' }, { uri: '0'}]
const kTake = Symbol('take')
export function take(obj: Record<string, number>, value: string): string
export function take(
  obj: Record<string, number>,
  value?: string,
): string | undefined
export function take(
  obj: { [s: string]: number; [kTake]?: string },
  value: string | undefined,
): string | undefined {
  if (value === undefined) {
    return
  }
  if (!(value in obj)) {
    obj[value] = Object.keys(obj).length
  }
  const kind = obj[kTake]
  return typeof kind === 'string'
    ? `${kind}(${obj[value]})`
    : String(obj[value])
}

export const constantDate = new Date(0).toISOString()
export const constantKeysetCursor = '0000000000000__bafycid'

const mapLeafValues = (
  obj: unknown,
  fn: (val: unknown) => unknown,
): unknown => {
  if (Array.isArray(obj)) {
    return obj.map((item) => mapLeafValues(item, fn))
  }
  if (obj && typeof obj === 'object') {
    return Object.entries(obj).reduce(
      (collect, [name, value]) =>
        Object.assign(collect, { [name]: mapLeafValues(value, fn) }),
      {},
    )
  }
  return fn(obj)
}

export const paginateAll = async <T extends { cursor?: string }>(
  fn: (cursor?: string) => Promise<T>,
  limit = Infinity,
): Promise<T[]> => {
  const results: T[] = []
  let cursor
  do {
    const res = await fn(cursor)
    results.push(res)
    cursor = res.cursor
  } while (cursor && results.length < limit)
  return results
}

// @NOTE mutates
export const stripViewer = <T extends { viewer?: unknown }>(
  val: T,
): Omit<T, 'viewer'> => {
  delete val.viewer
  return val
}

// @NOTE mutates
export function stripViewerFromPost(
  postUnknown: object,
  withType?: false,
): PostView
export function stripViewerFromPost(
  postUnknown: object,
  withType: true,
): $Typed<PostView>
export function stripViewerFromPost(
  postUnknown: object,
  withType = false,
): PostView {
  if ('$type' in postUnknown && !isPostView(postUnknown)) {
    throw new Error('Expected post view')
  }
  const post = postUnknown as PostView
  if (withType) {
    post.$type = 'app.bsky.feed.defs#postView'
  } else {
    delete post.$type
  }
  post.author = stripViewer(post.author)

  const recordEmbed = extractRecordEmbed(post.embed)

  if (recordEmbed) {
    recordEmbed.author = stripViewer(recordEmbed.author)
    recordEmbed.embeds?.forEach((deepEmbed) => {
      const deepRecordEmbed = extractRecordEmbed(deepEmbed)
      if (deepRecordEmbed) {
        deepRecordEmbed.author = stripViewer(deepRecordEmbed.author)
      }
    })
  }
  return stripViewer(post)
}

const extractRecordEmbed = (embed: PostView['embed']) =>
  isEmbedRecordView(embed)
    ? isViewRecord(embed.record)
      ? embed.record
      : undefined
    : isEmbedRecordWithMediaView(embed)
      ? isViewRecord(embed.record.record)
        ? embed.record.record
        : undefined
      : undefined

// @NOTE mutates
export const stripViewerFromThread = <T>(threadUnknown: T): T => {
  if (!isThreadViewPost(threadUnknown)) return threadUnknown

  const thread = threadUnknown as typeof threadUnknown & ThreadViewPost

  // @ts-expect-error "viewer" does not exist on type 'ThreadViewPost'
  delete thread.viewer

  thread.post = stripViewerFromPost(thread.post)
  if (isThreadViewPost(thread.parent)) {
    thread.parent = stripViewerFromThread(thread.parent)
  }
  if (thread.replies) {
    thread.replies = thread.replies.map(stripViewerFromThread)
  }
  return thread
}

// @NOTE mutates
export const stripViewerFromLabeler = (serviceUnknown: object): LabelerView => {
  if (
    '$type' in serviceUnknown &&
    !isLabelerView(serviceUnknown) &&
    !isLabelerViewDetailed(serviceUnknown)
  ) {
    throw new Error('Expected mod service view')
  }
  const labeler = serviceUnknown as LabelerView
  labeler.creator = stripViewer(labeler.creator)
  return stripViewer(labeler)
}

export async function startServer(app: Express) {
  return new Promise<{
    origin: string
    server: Server
    stop: () => Promise<void>
  }>((resolve, reject) => {
    const onListen = () => {
      const port = (server.address() as AddressInfo).port
      resolve({
        server,
        origin: `http://localhost:${port}`,
        stop: () => stopServer(server),
      })
      cleanup()
    }
    const onError = (err: Error) => {
      reject(err)
      cleanup()
    }
    const cleanup = () => {
      server.removeListener('listening', onListen)
      server.removeListener('error', onError)
    }

    const server = app
      .listen(0)
      .once('listening', onListen)
      .once('error', onError)
  })
}

export async function stopServer(server: Server) {
  return new Promise<void>((resolve, reject) => {
    server.close((err) => {
      if (err) {
        reject(err)
      } else {
        resolve()
      }
    })
  })
}
