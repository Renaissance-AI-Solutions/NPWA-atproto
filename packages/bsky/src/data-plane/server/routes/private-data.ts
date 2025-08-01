import { ServiceImpl } from '@connectrpc/connect'
import { keyBy } from '@atproto/common'
import {
  ChatPreference,
  FilterablePreference,
  Preference,
  Preferences,
} from '../../../lexicon/types/app/bsky/notification/defs'
import { Service } from '../../../proto/bsky_connect'
import {
  ChatNotificationInclude,
  ChatNotificationPreference,
  FilterableNotificationPreference,
  NotificationInclude,
  NotificationPreference,
  NotificationPreferences,
} from '../../../proto/bsky_pb'
import { Namespaces } from '../../../stash'
import { Database } from '../db'

export default (db: Database): Partial<ServiceImpl<typeof Service>> => ({
  async getNotificationPreferences(req) {
    const { dids } = req
    const res = await db.db
      .selectFrom('private_data')
      .selectAll()
      .where('actorDid', 'in', dids)
      .where('namespace', '=', Namespaces.AppBskyNotificationDefsPreferences)
      .where('key', '=', 'self')
      .execute()

    const byDid = keyBy(res, 'actorDid')
    const preferences = dids.map((did) => {
      const row = byDid.get(did)
      if (!row) {
        return {}
      }
      const p: Preferences = JSON.parse(row.payload)
      return lexToProtobuf(p, row.payload)
    })

    return { preferences }
  },
})

export const lexToProtobuf = (
  p: Preferences,
  json: string,
): NotificationPreferences => {
  return new NotificationPreferences({
    entry: Buffer.from(json),
    chat: lexChatPreferenceToProtobuf(p.chat),
    follow: lexFilterablePreferenceToProtobuf(p.follow),
    like: lexFilterablePreferenceToProtobuf(p.like),
    likeViaRepost: lexFilterablePreferenceToProtobuf(p.likeViaRepost),
    mention: lexFilterablePreferenceToProtobuf(p.mention),
    quote: lexFilterablePreferenceToProtobuf(p.quote),
    reply: lexFilterablePreferenceToProtobuf(p.reply),
    repost: lexFilterablePreferenceToProtobuf(p.repost),
    repostViaRepost: lexFilterablePreferenceToProtobuf(p.repostViaRepost),
    starterpackJoined: lexPreferenceToProtobuf(p.starterpackJoined),
    subscribedPost: lexPreferenceToProtobuf(p.subscribedPost),
    unverified: lexPreferenceToProtobuf(p.unverified),
    verified: lexPreferenceToProtobuf(p.verified),
  })
}

const lexChatPreferenceToProtobuf = (
  p: ChatPreference,
): ChatNotificationPreference =>
  new ChatNotificationPreference({
    include:
      p.include === 'accepted'
        ? ChatNotificationInclude.ACCEPTED
        : ChatNotificationInclude.ALL,
    push: { enabled: p.push ?? true },
  })

const lexFilterablePreferenceToProtobuf = (
  p: FilterablePreference,
): FilterableNotificationPreference =>
  new FilterableNotificationPreference({
    include:
      p.include === 'follows'
        ? NotificationInclude.FOLLOWS
        : NotificationInclude.ALL,
    list: { enabled: p.list ?? true },
    push: { enabled: p.push ?? true },
  })

const lexPreferenceToProtobuf = (p: Preference): NotificationPreference =>
  new NotificationPreference({
    list: { enabled: p.list ?? true },
    push: { enabled: p.push ?? true },
  })
