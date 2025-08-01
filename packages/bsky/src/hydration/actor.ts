import { mapDefined } from '@atproto/common'
import { DataPlaneClient } from '../data-plane/client'
import { Record as ProfileRecord } from '../lexicon/types/app/bsky/actor/profile'
import { Record as StatusRecord } from '../lexicon/types/app/bsky/actor/status'
import { Record as ChatDeclarationRecord } from '../lexicon/types/chat/bsky/actor/declaration'
import { VerificationMeta } from '../proto/bsky_pb'
import {
  HydrationMap,
  RecordInfo,
  parseRecord,
  parseString,
  safeTakedownRef,
} from './util'

export type Actor = {
  did: string
  handle?: string
  profile?: ProfileRecord
  profileCid?: string
  profileTakedownRef?: string
  sortedAt?: Date
  indexedAt?: Date
  takedownRef?: string
  isLabeler: boolean
  allowIncomingChatsFrom?: string
  upstreamStatus?: string
  createdAt?: Date
  priorityNotifications: boolean
  trustedVerifier?: boolean
  verifications: VerificationHydrationState[]
  status?: RecordInfo<StatusRecord>
}

export type VerificationHydrationState = {
  issuer: string
  uri: string
  handle: string
  displayName: string
  createdAt: string
}

export type VerificationMetaRequired = Required<VerificationMeta>

export type Actors = HydrationMap<Actor>

export type ChatDeclaration = RecordInfo<ChatDeclarationRecord>

export type ChatDeclarations = HydrationMap<ChatDeclaration>

export type Status = RecordInfo<StatusRecord>
export type Statuses = HydrationMap<Status>

export type ProfileViewerState = {
  muted?: boolean
  mutedByList?: string
  blockedBy?: string
  blocking?: string
  blockedByList?: string
  blockingByList?: string
  following?: string
  followedBy?: string
  knownFollowers?: {
    count: number
    followers: string[]
  }
}

export type ProfileViewerStates = HydrationMap<ProfileViewerState>

export type KnownFollowers = HydrationMap<ProfileViewerState['knownFollowers']>

export type ProfileAgg = {
  followers: number
  follows: number
  posts: number
  lists: number
  feeds: number
  starterPacks: number
}

export type ProfileAggs = HydrationMap<ProfileAgg>

export class ActorHydrator {
  constructor(public dataplane: DataPlaneClient) {}

  async getRepoRevSafe(did: string | null): Promise<string | null> {
    if (!did) return null
    try {
      const res = await this.dataplane.getLatestRev({ actorDid: did })
      return parseString(res.rev) ?? null
    } catch {
      return null
    }
  }

  async getDids(
    handleOrDids: string[],
    opts?: { lookupUnidirectional?: boolean },
  ): Promise<(string | undefined)[]> {
    const handles = handleOrDids.filter((actor) => !actor.startsWith('did:'))
    const res = handles.length
      ? await this.dataplane.getDidsByHandles({
          handles,
          lookupUnidirectional: opts?.lookupUnidirectional,
        })
      : { dids: [] }
    const didByHandle = handles.reduce(
      (acc, cur, i) => {
        const did = res.dids[i]
        if (did && did.length > 0) {
          return acc.set(cur, did)
        }
        return acc
      },
      new Map() as Map<string, string>,
    )
    return handleOrDids.map((id) =>
      id.startsWith('did:') ? id : didByHandle.get(id),
    )
  }

  async getDidsDefined(handleOrDids: string[]): Promise<string[]> {
    const res = await this.getDids(handleOrDids)
    // @ts-ignore
    return res.filter((did) => did !== undefined)
  }

  async getActors(
    dids: string[],
    opts: {
      includeTakedowns?: boolean
      skipCacheForDids?: string[]
    } = {},
  ): Promise<Actors> {
    const { includeTakedowns = false, skipCacheForDids } = opts
    if (!dids.length) return new HydrationMap<Actor>()
    const res = await this.dataplane.getActors({ dids, skipCacheForDids })
    return dids.reduce((acc, did, i) => {
      const actor = res.actors[i]
      const isNoHosted =
        actor.takenDown ||
        (actor.upstreamStatus && actor.upstreamStatus !== 'active')
      if (
        !actor.exists ||
        (isNoHosted && !includeTakedowns) ||
        !!actor.tombstonedAt
      ) {
        return acc.set(did, null)
      }

      const profile = actor.profile
        ? parseRecord<ProfileRecord>(actor.profile, includeTakedowns)
        : undefined

      const status = actor.statusRecord
        ? parseRecord<StatusRecord>(actor.statusRecord, includeTakedowns)
        : undefined

      const verifications = mapDefined(
        Object.entries(actor.verifiedBy),
        ([actorDid, verificationMeta]) => {
          if (
            verificationMeta.handle &&
            verificationMeta.rkey &&
            verificationMeta.sortedAt
          ) {
            return {
              issuer: actorDid,
              uri: `at://${actorDid}/app.bsky.graph.verification/${verificationMeta.rkey}`,
              handle: verificationMeta.handle,
              displayName: verificationMeta.displayName,
              createdAt: verificationMeta.sortedAt.toDate().toISOString(),
            }
          }
          // Filter out the verification meta that doesn't contain all info.
          return undefined
        },
      )

      return acc.set(did, {
        did,
        handle: parseString(actor.handle),
        profile: profile?.record,
        profileCid: profile?.cid,
        profileTakedownRef: profile?.takedownRef,
        sortedAt: profile?.sortedAt,
        indexedAt: profile?.indexedAt,
        takedownRef: safeTakedownRef(actor),
        isLabeler: actor.labeler ?? false,
        allowIncomingChatsFrom: actor.allowIncomingChatsFrom || undefined,
        upstreamStatus: actor.upstreamStatus || undefined,
        createdAt: actor.createdAt?.toDate(),
        priorityNotifications: actor.priorityNotifications,
        trustedVerifier: actor.trustedVerifier,
        verifications,
        status: status,
      })
    }, new HydrationMap<Actor>())
  }

  async getChatDeclarations(
    uris: string[],
    includeTakedowns = false,
  ): Promise<ChatDeclarations> {
    if (!uris.length) return new HydrationMap<ChatDeclaration>()
    const res = await this.dataplane.getActorChatDeclarationRecords({ uris })
    return uris.reduce((acc, uri, i) => {
      const record = parseRecord<ChatDeclarationRecord>(
        res.records[i],
        includeTakedowns,
      )
      return acc.set(uri, record ?? null)
    }, new HydrationMap<ChatDeclaration>())
  }

  async getStatus(uris: string[], includeTakedowns = false): Promise<Statuses> {
    if (!uris.length) return new HydrationMap<Status>()
    const res = await this.dataplane.getStatusRecords({ uris })
    return uris.reduce((acc, uri, i) => {
      const record = parseRecord<StatusRecord>(res.records[i], includeTakedowns)
      return acc.set(uri, record ?? null)
    }, new HydrationMap<Status>())
  }

  // "naive" because this method does not verify the existence of the list itself
  // a later check in the main hydrator will remove list uris that have been deleted or
  // repurposed to "curate lists"
  async getProfileViewerStatesNaive(
    dids: string[],
    viewer: string,
  ): Promise<ProfileViewerStates> {
    if (!dids.length) return new HydrationMap<ProfileViewerState>()
    const res = await this.dataplane.getRelationships({
      actorDid: viewer,
      targetDids: dids,
    })
    return dids.reduce((acc, did, i) => {
      const rels = res.relationships[i]
      if (viewer === did) {
        // ignore self-follows, self-mutes, self-blocks
        return acc.set(did, {})
      }
      return acc.set(did, {
        muted: rels.muted ?? false,
        mutedByList: parseString(rels.mutedByList),
        blockedBy: parseString(rels.blockedBy),
        blocking: parseString(rels.blocking),
        blockedByList: parseString(rels.blockedByList),
        blockingByList: parseString(rels.blockingByList),
        following: parseString(rels.following),
        followedBy: parseString(rels.followedBy),
      })
    }, new HydrationMap<ProfileViewerState>())
  }

  async getKnownFollowers(
    dids: string[],
    viewer: string | null,
  ): Promise<KnownFollowers> {
    if (!viewer) return new HydrationMap<ProfileViewerState['knownFollowers']>()
    const { results: knownFollowersResults } = await this.dataplane
      .getFollowsFollowing(
        {
          actorDid: viewer,
          targetDids: dids,
        },
        {
          signal: AbortSignal.timeout(100),
        },
      )
      .catch(() => ({ results: [] }))
    return dids.reduce((acc, did, i) => {
      const result = knownFollowersResults[i]?.dids
      return acc.set(
        did,
        result && result.length > 0
          ? {
              count: result.length,
              followers: result.slice(0, 5),
            }
          : undefined,
      )
    }, new HydrationMap<ProfileViewerState['knownFollowers']>())
  }

  async getProfileAggregates(dids: string[]): Promise<ProfileAggs> {
    if (!dids.length) return new HydrationMap<ProfileAgg>()
    const counts = await this.dataplane.getCountsForUsers({ dids })
    return dids.reduce((acc, did, i) => {
      return acc.set(did, {
        followers: counts.followers[i] ?? 0,
        follows: counts.following[i] ?? 0,
        posts: counts.posts[i] ?? 0,
        lists: counts.lists[i] ?? 0,
        feeds: counts.feeds[i] ?? 0,
        starterPacks: counts.starterPacks[i] ?? 0,
      })
    }, new HydrationMap<ProfileAgg>())
  }
}
