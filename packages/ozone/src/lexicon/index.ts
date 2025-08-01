/**
 * GENERATED CODE - DO NOT MODIFY
 */
import {
  createServer as createXrpcServer,
  Server as XrpcServer,
  type Options as XrpcOptions,
  type AuthVerifier,
  type StreamAuthVerifier,
} from '@atproto/xrpc-server'
import { schemas } from './lexicons.js'
import * as ComAtprotoAdminDeleteAccount from './types/com/atproto/admin/deleteAccount.js'
import * as ComAtprotoAdminDisableAccountInvites from './types/com/atproto/admin/disableAccountInvites.js'
import * as ComAtprotoAdminDisableInviteCodes from './types/com/atproto/admin/disableInviteCodes.js'
import * as ComAtprotoAdminEnableAccountInvites from './types/com/atproto/admin/enableAccountInvites.js'
import * as ComAtprotoAdminGetAccountInfo from './types/com/atproto/admin/getAccountInfo.js'
import * as ComAtprotoAdminGetAccountInfos from './types/com/atproto/admin/getAccountInfos.js'
import * as ComAtprotoAdminGetInviteCodes from './types/com/atproto/admin/getInviteCodes.js'
import * as ComAtprotoAdminGetSubjectStatus from './types/com/atproto/admin/getSubjectStatus.js'
import * as ComAtprotoAdminSearchAccounts from './types/com/atproto/admin/searchAccounts.js'
import * as ComAtprotoAdminSendEmail from './types/com/atproto/admin/sendEmail.js'
import * as ComAtprotoAdminUpdateAccountEmail from './types/com/atproto/admin/updateAccountEmail.js'
import * as ComAtprotoAdminUpdateAccountHandle from './types/com/atproto/admin/updateAccountHandle.js'
import * as ComAtprotoAdminUpdateAccountPassword from './types/com/atproto/admin/updateAccountPassword.js'
import * as ComAtprotoAdminUpdateAccountSigningKey from './types/com/atproto/admin/updateAccountSigningKey.js'
import * as ComAtprotoAdminUpdateSubjectStatus from './types/com/atproto/admin/updateSubjectStatus.js'
import * as ComAtprotoIdentityGetRecommendedDidCredentials from './types/com/atproto/identity/getRecommendedDidCredentials.js'
import * as ComAtprotoIdentityRefreshIdentity from './types/com/atproto/identity/refreshIdentity.js'
import * as ComAtprotoIdentityRequestPlcOperationSignature from './types/com/atproto/identity/requestPlcOperationSignature.js'
import * as ComAtprotoIdentityResolveDid from './types/com/atproto/identity/resolveDid.js'
import * as ComAtprotoIdentityResolveHandle from './types/com/atproto/identity/resolveHandle.js'
import * as ComAtprotoIdentityResolveIdentity from './types/com/atproto/identity/resolveIdentity.js'
import * as ComAtprotoIdentitySignPlcOperation from './types/com/atproto/identity/signPlcOperation.js'
import * as ComAtprotoIdentitySubmitPlcOperation from './types/com/atproto/identity/submitPlcOperation.js'
import * as ComAtprotoIdentityUpdateHandle from './types/com/atproto/identity/updateHandle.js'
import * as ComAtprotoLabelQueryLabels from './types/com/atproto/label/queryLabels.js'
import * as ComAtprotoLabelSubscribeLabels from './types/com/atproto/label/subscribeLabels.js'
import * as ComAtprotoModerationCreateReport from './types/com/atproto/moderation/createReport.js'
import * as ComAtprotoRepoApplyWrites from './types/com/atproto/repo/applyWrites.js'
import * as ComAtprotoRepoCreateRecord from './types/com/atproto/repo/createRecord.js'
import * as ComAtprotoRepoDeleteRecord from './types/com/atproto/repo/deleteRecord.js'
import * as ComAtprotoRepoDescribeRepo from './types/com/atproto/repo/describeRepo.js'
import * as ComAtprotoRepoGetRecord from './types/com/atproto/repo/getRecord.js'
import * as ComAtprotoRepoImportRepo from './types/com/atproto/repo/importRepo.js'
import * as ComAtprotoRepoListMissingBlobs from './types/com/atproto/repo/listMissingBlobs.js'
import * as ComAtprotoRepoListRecords from './types/com/atproto/repo/listRecords.js'
import * as ComAtprotoRepoPutRecord from './types/com/atproto/repo/putRecord.js'
import * as ComAtprotoRepoUploadBlob from './types/com/atproto/repo/uploadBlob.js'
import * as ComAtprotoServerActivateAccount from './types/com/atproto/server/activateAccount.js'
import * as ComAtprotoServerCheckAccountStatus from './types/com/atproto/server/checkAccountStatus.js'
import * as ComAtprotoServerConfirmEmail from './types/com/atproto/server/confirmEmail.js'
import * as ComAtprotoServerCreateAccount from './types/com/atproto/server/createAccount.js'
import * as ComAtprotoServerCreateAppPassword from './types/com/atproto/server/createAppPassword.js'
import * as ComAtprotoServerCreateInviteCode from './types/com/atproto/server/createInviteCode.js'
import * as ComAtprotoServerCreateInviteCodes from './types/com/atproto/server/createInviteCodes.js'
import * as ComAtprotoServerCreateSession from './types/com/atproto/server/createSession.js'
import * as ComAtprotoServerDeactivateAccount from './types/com/atproto/server/deactivateAccount.js'
import * as ComAtprotoServerDeleteAccount from './types/com/atproto/server/deleteAccount.js'
import * as ComAtprotoServerDeleteSession from './types/com/atproto/server/deleteSession.js'
import * as ComAtprotoServerDescribeServer from './types/com/atproto/server/describeServer.js'
import * as ComAtprotoServerGetAccountInviteCodes from './types/com/atproto/server/getAccountInviteCodes.js'
import * as ComAtprotoServerGetServiceAuth from './types/com/atproto/server/getServiceAuth.js'
import * as ComAtprotoServerGetSession from './types/com/atproto/server/getSession.js'
import * as ComAtprotoServerListAppPasswords from './types/com/atproto/server/listAppPasswords.js'
import * as ComAtprotoServerRefreshSession from './types/com/atproto/server/refreshSession.js'
import * as ComAtprotoServerRequestAccountDelete from './types/com/atproto/server/requestAccountDelete.js'
import * as ComAtprotoServerRequestEmailConfirmation from './types/com/atproto/server/requestEmailConfirmation.js'
import * as ComAtprotoServerRequestEmailUpdate from './types/com/atproto/server/requestEmailUpdate.js'
import * as ComAtprotoServerRequestPasswordReset from './types/com/atproto/server/requestPasswordReset.js'
import * as ComAtprotoServerReserveSigningKey from './types/com/atproto/server/reserveSigningKey.js'
import * as ComAtprotoServerResetPassword from './types/com/atproto/server/resetPassword.js'
import * as ComAtprotoServerRevokeAppPassword from './types/com/atproto/server/revokeAppPassword.js'
import * as ComAtprotoServerUpdateEmail from './types/com/atproto/server/updateEmail.js'
import * as ComAtprotoSyncGetBlob from './types/com/atproto/sync/getBlob.js'
import * as ComAtprotoSyncGetBlocks from './types/com/atproto/sync/getBlocks.js'
import * as ComAtprotoSyncGetCheckout from './types/com/atproto/sync/getCheckout.js'
import * as ComAtprotoSyncGetHead from './types/com/atproto/sync/getHead.js'
import * as ComAtprotoSyncGetHostStatus from './types/com/atproto/sync/getHostStatus.js'
import * as ComAtprotoSyncGetLatestCommit from './types/com/atproto/sync/getLatestCommit.js'
import * as ComAtprotoSyncGetRecord from './types/com/atproto/sync/getRecord.js'
import * as ComAtprotoSyncGetRepo from './types/com/atproto/sync/getRepo.js'
import * as ComAtprotoSyncGetRepoStatus from './types/com/atproto/sync/getRepoStatus.js'
import * as ComAtprotoSyncListBlobs from './types/com/atproto/sync/listBlobs.js'
import * as ComAtprotoSyncListHosts from './types/com/atproto/sync/listHosts.js'
import * as ComAtprotoSyncListRepos from './types/com/atproto/sync/listRepos.js'
import * as ComAtprotoSyncListReposByCollection from './types/com/atproto/sync/listReposByCollection.js'
import * as ComAtprotoSyncNotifyOfUpdate from './types/com/atproto/sync/notifyOfUpdate.js'
import * as ComAtprotoSyncRequestCrawl from './types/com/atproto/sync/requestCrawl.js'
import * as ComAtprotoSyncSubscribeRepos from './types/com/atproto/sync/subscribeRepos.js'
import * as ComAtprotoTempAddReservedHandle from './types/com/atproto/temp/addReservedHandle.js'
import * as ComAtprotoTempCheckSignupQueue from './types/com/atproto/temp/checkSignupQueue.js'
import * as ComAtprotoTempFetchLabels from './types/com/atproto/temp/fetchLabels.js'
import * as ComAtprotoTempRequestPhoneVerification from './types/com/atproto/temp/requestPhoneVerification.js'
import * as AppBskyActorGetPreferences from './types/app/bsky/actor/getPreferences.js'
import * as AppBskyActorGetProfile from './types/app/bsky/actor/getProfile.js'
import * as AppBskyActorGetProfiles from './types/app/bsky/actor/getProfiles.js'
import * as AppBskyActorGetSuggestions from './types/app/bsky/actor/getSuggestions.js'
import * as AppBskyActorPutPreferences from './types/app/bsky/actor/putPreferences.js'
import * as AppBskyActorSearchActors from './types/app/bsky/actor/searchActors.js'
import * as AppBskyActorSearchActorsTypeahead from './types/app/bsky/actor/searchActorsTypeahead.js'
import * as AppBskyFeedDescribeFeedGenerator from './types/app/bsky/feed/describeFeedGenerator.js'
import * as AppBskyFeedGetActorFeeds from './types/app/bsky/feed/getActorFeeds.js'
import * as AppBskyFeedGetActorLikes from './types/app/bsky/feed/getActorLikes.js'
import * as AppBskyFeedGetAuthorFeed from './types/app/bsky/feed/getAuthorFeed.js'
import * as AppBskyFeedGetFeed from './types/app/bsky/feed/getFeed.js'
import * as AppBskyFeedGetFeedGenerator from './types/app/bsky/feed/getFeedGenerator.js'
import * as AppBskyFeedGetFeedGenerators from './types/app/bsky/feed/getFeedGenerators.js'
import * as AppBskyFeedGetFeedSkeleton from './types/app/bsky/feed/getFeedSkeleton.js'
import * as AppBskyFeedGetLikes from './types/app/bsky/feed/getLikes.js'
import * as AppBskyFeedGetListFeed from './types/app/bsky/feed/getListFeed.js'
import * as AppBskyFeedGetPostThread from './types/app/bsky/feed/getPostThread.js'
import * as AppBskyFeedGetPosts from './types/app/bsky/feed/getPosts.js'
import * as AppBskyFeedGetQuotes from './types/app/bsky/feed/getQuotes.js'
import * as AppBskyFeedGetRepostedBy from './types/app/bsky/feed/getRepostedBy.js'
import * as AppBskyFeedGetSuggestedFeeds from './types/app/bsky/feed/getSuggestedFeeds.js'
import * as AppBskyFeedGetTimeline from './types/app/bsky/feed/getTimeline.js'
import * as AppBskyFeedSearchPosts from './types/app/bsky/feed/searchPosts.js'
import * as AppBskyFeedSendInteractions from './types/app/bsky/feed/sendInteractions.js'
import * as AppBskyGraphGetActorStarterPacks from './types/app/bsky/graph/getActorStarterPacks.js'
import * as AppBskyGraphGetBlocks from './types/app/bsky/graph/getBlocks.js'
import * as AppBskyGraphGetFollowers from './types/app/bsky/graph/getFollowers.js'
import * as AppBskyGraphGetFollows from './types/app/bsky/graph/getFollows.js'
import * as AppBskyGraphGetKnownFollowers from './types/app/bsky/graph/getKnownFollowers.js'
import * as AppBskyGraphGetList from './types/app/bsky/graph/getList.js'
import * as AppBskyGraphGetListBlocks from './types/app/bsky/graph/getListBlocks.js'
import * as AppBskyGraphGetListMutes from './types/app/bsky/graph/getListMutes.js'
import * as AppBskyGraphGetLists from './types/app/bsky/graph/getLists.js'
import * as AppBskyGraphGetMutes from './types/app/bsky/graph/getMutes.js'
import * as AppBskyGraphGetRelationships from './types/app/bsky/graph/getRelationships.js'
import * as AppBskyGraphGetStarterPack from './types/app/bsky/graph/getStarterPack.js'
import * as AppBskyGraphGetStarterPacks from './types/app/bsky/graph/getStarterPacks.js'
import * as AppBskyGraphGetSuggestedFollowsByActor from './types/app/bsky/graph/getSuggestedFollowsByActor.js'
import * as AppBskyGraphMuteActor from './types/app/bsky/graph/muteActor.js'
import * as AppBskyGraphMuteActorList from './types/app/bsky/graph/muteActorList.js'
import * as AppBskyGraphMuteThread from './types/app/bsky/graph/muteThread.js'
import * as AppBskyGraphSearchStarterPacks from './types/app/bsky/graph/searchStarterPacks.js'
import * as AppBskyGraphUnmuteActor from './types/app/bsky/graph/unmuteActor.js'
import * as AppBskyGraphUnmuteActorList from './types/app/bsky/graph/unmuteActorList.js'
import * as AppBskyGraphUnmuteThread from './types/app/bsky/graph/unmuteThread.js'
import * as AppBskyLabelerGetServices from './types/app/bsky/labeler/getServices.js'
import * as AppBskyNotificationGetPreferences from './types/app/bsky/notification/getPreferences.js'
import * as AppBskyNotificationGetUnreadCount from './types/app/bsky/notification/getUnreadCount.js'
import * as AppBskyNotificationListActivitySubscriptions from './types/app/bsky/notification/listActivitySubscriptions.js'
import * as AppBskyNotificationListNotifications from './types/app/bsky/notification/listNotifications.js'
import * as AppBskyNotificationPutActivitySubscription from './types/app/bsky/notification/putActivitySubscription.js'
import * as AppBskyNotificationPutPreferences from './types/app/bsky/notification/putPreferences.js'
import * as AppBskyNotificationPutPreferencesV2 from './types/app/bsky/notification/putPreferencesV2.js'
import * as AppBskyNotificationRegisterPush from './types/app/bsky/notification/registerPush.js'
import * as AppBskyNotificationUpdateSeen from './types/app/bsky/notification/updateSeen.js'
import * as AppBskySourcesAddComment from './types/app/bsky/sources/addComment.js'
import * as AppBskySourcesCreate from './types/app/bsky/sources/create.js'
import * as AppBskySourcesGet from './types/app/bsky/sources/get.js'
import * as AppBskySourcesGetComments from './types/app/bsky/sources/getComments.js'
import * as AppBskySourcesList from './types/app/bsky/sources/list.js'
import * as AppBskySourcesVote from './types/app/bsky/sources/vote.js'
import * as AppBskyUnspeccedGetConfig from './types/app/bsky/unspecced/getConfig.js'
import * as AppBskyUnspeccedGetPopularFeedGenerators from './types/app/bsky/unspecced/getPopularFeedGenerators.js'
import * as AppBskyUnspeccedGetPostThreadOtherV2 from './types/app/bsky/unspecced/getPostThreadOtherV2.js'
import * as AppBskyUnspeccedGetPostThreadV2 from './types/app/bsky/unspecced/getPostThreadV2.js'
import * as AppBskyUnspeccedGetSuggestedFeeds from './types/app/bsky/unspecced/getSuggestedFeeds.js'
import * as AppBskyUnspeccedGetSuggestedFeedsSkeleton from './types/app/bsky/unspecced/getSuggestedFeedsSkeleton.js'
import * as AppBskyUnspeccedGetSuggestedStarterPacks from './types/app/bsky/unspecced/getSuggestedStarterPacks.js'
import * as AppBskyUnspeccedGetSuggestedStarterPacksSkeleton from './types/app/bsky/unspecced/getSuggestedStarterPacksSkeleton.js'
import * as AppBskyUnspeccedGetSuggestedUsers from './types/app/bsky/unspecced/getSuggestedUsers.js'
import * as AppBskyUnspeccedGetSuggestedUsersSkeleton from './types/app/bsky/unspecced/getSuggestedUsersSkeleton.js'
import * as AppBskyUnspeccedGetSuggestionsSkeleton from './types/app/bsky/unspecced/getSuggestionsSkeleton.js'
import * as AppBskyUnspeccedGetTaggedSuggestions from './types/app/bsky/unspecced/getTaggedSuggestions.js'
import * as AppBskyUnspeccedGetTrendingTopics from './types/app/bsky/unspecced/getTrendingTopics.js'
import * as AppBskyUnspeccedGetTrends from './types/app/bsky/unspecced/getTrends.js'
import * as AppBskyUnspeccedGetTrendsSkeleton from './types/app/bsky/unspecced/getTrendsSkeleton.js'
import * as AppBskyUnspeccedSearchActorsSkeleton from './types/app/bsky/unspecced/searchActorsSkeleton.js'
import * as AppBskyUnspeccedSearchPostsSkeleton from './types/app/bsky/unspecced/searchPostsSkeleton.js'
import * as AppBskyUnspeccedSearchStarterPacksSkeleton from './types/app/bsky/unspecced/searchStarterPacksSkeleton.js'
import * as AppBskyVideoGetJobStatus from './types/app/bsky/video/getJobStatus.js'
import * as AppBskyVideoGetUploadLimits from './types/app/bsky/video/getUploadLimits.js'
import * as AppBskyVideoUploadVideo from './types/app/bsky/video/uploadVideo.js'
import * as ChatBskyActorDeleteAccount from './types/chat/bsky/actor/deleteAccount.js'
import * as ChatBskyActorExportAccountData from './types/chat/bsky/actor/exportAccountData.js'
import * as ChatBskyConvoAcceptConvo from './types/chat/bsky/convo/acceptConvo.js'
import * as ChatBskyConvoAddReaction from './types/chat/bsky/convo/addReaction.js'
import * as ChatBskyConvoDeleteMessageForSelf from './types/chat/bsky/convo/deleteMessageForSelf.js'
import * as ChatBskyConvoGetConvo from './types/chat/bsky/convo/getConvo.js'
import * as ChatBskyConvoGetConvoAvailability from './types/chat/bsky/convo/getConvoAvailability.js'
import * as ChatBskyConvoGetConvoForMembers from './types/chat/bsky/convo/getConvoForMembers.js'
import * as ChatBskyConvoGetLog from './types/chat/bsky/convo/getLog.js'
import * as ChatBskyConvoGetMessages from './types/chat/bsky/convo/getMessages.js'
import * as ChatBskyConvoLeaveConvo from './types/chat/bsky/convo/leaveConvo.js'
import * as ChatBskyConvoListConvos from './types/chat/bsky/convo/listConvos.js'
import * as ChatBskyConvoMuteConvo from './types/chat/bsky/convo/muteConvo.js'
import * as ChatBskyConvoRemoveReaction from './types/chat/bsky/convo/removeReaction.js'
import * as ChatBskyConvoSendMessage from './types/chat/bsky/convo/sendMessage.js'
import * as ChatBskyConvoSendMessageBatch from './types/chat/bsky/convo/sendMessageBatch.js'
import * as ChatBskyConvoUnmuteConvo from './types/chat/bsky/convo/unmuteConvo.js'
import * as ChatBskyConvoUpdateAllRead from './types/chat/bsky/convo/updateAllRead.js'
import * as ChatBskyConvoUpdateRead from './types/chat/bsky/convo/updateRead.js'
import * as ChatBskyModerationGetActorMetadata from './types/chat/bsky/moderation/getActorMetadata.js'
import * as ChatBskyModerationGetMessageContext from './types/chat/bsky/moderation/getMessageContext.js'
import * as ChatBskyModerationUpdateActorAccess from './types/chat/bsky/moderation/updateActorAccess.js'
import * as ToolsOzoneCommunicationCreateTemplate from './types/tools/ozone/communication/createTemplate.js'
import * as ToolsOzoneCommunicationDeleteTemplate from './types/tools/ozone/communication/deleteTemplate.js'
import * as ToolsOzoneCommunicationListTemplates from './types/tools/ozone/communication/listTemplates.js'
import * as ToolsOzoneCommunicationUpdateTemplate from './types/tools/ozone/communication/updateTemplate.js'
import * as ToolsOzoneHostingGetAccountHistory from './types/tools/ozone/hosting/getAccountHistory.js'
import * as ToolsOzoneModerationEmitEvent from './types/tools/ozone/moderation/emitEvent.js'
import * as ToolsOzoneModerationGetEvent from './types/tools/ozone/moderation/getEvent.js'
import * as ToolsOzoneModerationGetRecord from './types/tools/ozone/moderation/getRecord.js'
import * as ToolsOzoneModerationGetRecords from './types/tools/ozone/moderation/getRecords.js'
import * as ToolsOzoneModerationGetRepo from './types/tools/ozone/moderation/getRepo.js'
import * as ToolsOzoneModerationGetReporterStats from './types/tools/ozone/moderation/getReporterStats.js'
import * as ToolsOzoneModerationGetRepos from './types/tools/ozone/moderation/getRepos.js'
import * as ToolsOzoneModerationGetSubjects from './types/tools/ozone/moderation/getSubjects.js'
import * as ToolsOzoneModerationQueryEvents from './types/tools/ozone/moderation/queryEvents.js'
import * as ToolsOzoneModerationQueryStatuses from './types/tools/ozone/moderation/queryStatuses.js'
import * as ToolsOzoneModerationSearchRepos from './types/tools/ozone/moderation/searchRepos.js'
import * as ToolsOzoneServerGetConfig from './types/tools/ozone/server/getConfig.js'
import * as ToolsOzoneSetAddValues from './types/tools/ozone/set/addValues.js'
import * as ToolsOzoneSetDeleteSet from './types/tools/ozone/set/deleteSet.js'
import * as ToolsOzoneSetDeleteValues from './types/tools/ozone/set/deleteValues.js'
import * as ToolsOzoneSetGetValues from './types/tools/ozone/set/getValues.js'
import * as ToolsOzoneSetQuerySets from './types/tools/ozone/set/querySets.js'
import * as ToolsOzoneSetUpsertSet from './types/tools/ozone/set/upsertSet.js'
import * as ToolsOzoneSettingListOptions from './types/tools/ozone/setting/listOptions.js'
import * as ToolsOzoneSettingRemoveOptions from './types/tools/ozone/setting/removeOptions.js'
import * as ToolsOzoneSettingUpsertOption from './types/tools/ozone/setting/upsertOption.js'
import * as ToolsOzoneSignatureFindCorrelation from './types/tools/ozone/signature/findCorrelation.js'
import * as ToolsOzoneSignatureFindRelatedAccounts from './types/tools/ozone/signature/findRelatedAccounts.js'
import * as ToolsOzoneSignatureSearchAccounts from './types/tools/ozone/signature/searchAccounts.js'
import * as ToolsOzoneTeamAddMember from './types/tools/ozone/team/addMember.js'
import * as ToolsOzoneTeamDeleteMember from './types/tools/ozone/team/deleteMember.js'
import * as ToolsOzoneTeamListMembers from './types/tools/ozone/team/listMembers.js'
import * as ToolsOzoneTeamUpdateMember from './types/tools/ozone/team/updateMember.js'
import * as ToolsOzoneVerificationGrantVerifications from './types/tools/ozone/verification/grantVerifications.js'
import * as ToolsOzoneVerificationListVerifications from './types/tools/ozone/verification/listVerifications.js'
import * as ToolsOzoneVerificationRevokeVerifications from './types/tools/ozone/verification/revokeVerifications.js'

export const COM_ATPROTO_MODERATION = {
  DefsReasonSpam: 'com.atproto.moderation.defs#reasonSpam',
  DefsReasonViolation: 'com.atproto.moderation.defs#reasonViolation',
  DefsReasonMisleading: 'com.atproto.moderation.defs#reasonMisleading',
  DefsReasonSexual: 'com.atproto.moderation.defs#reasonSexual',
  DefsReasonRude: 'com.atproto.moderation.defs#reasonRude',
  DefsReasonOther: 'com.atproto.moderation.defs#reasonOther',
  DefsReasonAppeal: 'com.atproto.moderation.defs#reasonAppeal',
}
export const APP_BSKY_ACTOR = {
  StatusLive: 'app.bsky.actor.status#live',
}
export const APP_BSKY_FEED = {
  DefsRequestLess: 'app.bsky.feed.defs#requestLess',
  DefsRequestMore: 'app.bsky.feed.defs#requestMore',
  DefsClickthroughItem: 'app.bsky.feed.defs#clickthroughItem',
  DefsClickthroughAuthor: 'app.bsky.feed.defs#clickthroughAuthor',
  DefsClickthroughReposter: 'app.bsky.feed.defs#clickthroughReposter',
  DefsClickthroughEmbed: 'app.bsky.feed.defs#clickthroughEmbed',
  DefsContentModeUnspecified: 'app.bsky.feed.defs#contentModeUnspecified',
  DefsContentModeVideo: 'app.bsky.feed.defs#contentModeVideo',
  DefsInteractionSeen: 'app.bsky.feed.defs#interactionSeen',
  DefsInteractionLike: 'app.bsky.feed.defs#interactionLike',
  DefsInteractionRepost: 'app.bsky.feed.defs#interactionRepost',
  DefsInteractionReply: 'app.bsky.feed.defs#interactionReply',
  DefsInteractionQuote: 'app.bsky.feed.defs#interactionQuote',
  DefsInteractionShare: 'app.bsky.feed.defs#interactionShare',
}
export const APP_BSKY_GRAPH = {
  DefsModlist: 'app.bsky.graph.defs#modlist',
  DefsCuratelist: 'app.bsky.graph.defs#curatelist',
  DefsReferencelist: 'app.bsky.graph.defs#referencelist',
}
export const TOOLS_OZONE_MODERATION = {
  DefsReviewOpen: 'tools.ozone.moderation.defs#reviewOpen',
  DefsReviewEscalated: 'tools.ozone.moderation.defs#reviewEscalated',
  DefsReviewClosed: 'tools.ozone.moderation.defs#reviewClosed',
  DefsReviewNone: 'tools.ozone.moderation.defs#reviewNone',
}
export const TOOLS_OZONE_TEAM = {
  DefsRoleAdmin: 'tools.ozone.team.defs#roleAdmin',
  DefsRoleModerator: 'tools.ozone.team.defs#roleModerator',
  DefsRoleTriage: 'tools.ozone.team.defs#roleTriage',
  DefsRoleVerifier: 'tools.ozone.team.defs#roleVerifier',
}

export function createServer(options?: XrpcOptions): Server {
  return new Server(options)
}

export class Server {
  xrpc: XrpcServer
  com: ComNS
  app: AppNS
  chat: ChatNS
  tools: ToolsNS

  constructor(options?: XrpcOptions) {
    this.xrpc = createXrpcServer(schemas, options)
    this.com = new ComNS(this)
    this.app = new AppNS(this)
    this.chat = new ChatNS(this)
    this.tools = new ToolsNS(this)
  }
}

export class ComNS {
  _server: Server
  atproto: ComAtprotoNS

  constructor(server: Server) {
    this._server = server
    this.atproto = new ComAtprotoNS(server)
  }
}

export class ComAtprotoNS {
  _server: Server
  admin: ComAtprotoAdminNS
  identity: ComAtprotoIdentityNS
  label: ComAtprotoLabelNS
  lexicon: ComAtprotoLexiconNS
  moderation: ComAtprotoModerationNS
  repo: ComAtprotoRepoNS
  server: ComAtprotoServerNS
  sync: ComAtprotoSyncNS
  temp: ComAtprotoTempNS

  constructor(server: Server) {
    this._server = server
    this.admin = new ComAtprotoAdminNS(server)
    this.identity = new ComAtprotoIdentityNS(server)
    this.label = new ComAtprotoLabelNS(server)
    this.lexicon = new ComAtprotoLexiconNS(server)
    this.moderation = new ComAtprotoModerationNS(server)
    this.repo = new ComAtprotoRepoNS(server)
    this.server = new ComAtprotoServerNS(server)
    this.sync = new ComAtprotoSyncNS(server)
    this.temp = new ComAtprotoTempNS(server)
  }
}

export class ComAtprotoAdminNS {
  _server: Server

  constructor(server: Server) {
    this._server = server
  }

  deleteAccount<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoAdminDeleteAccount.Handler<ExtractAuth<AV>>,
      ComAtprotoAdminDeleteAccount.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.admin.deleteAccount' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  disableAccountInvites<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoAdminDisableAccountInvites.Handler<ExtractAuth<AV>>,
      ComAtprotoAdminDisableAccountInvites.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.admin.disableAccountInvites' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  disableInviteCodes<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoAdminDisableInviteCodes.Handler<ExtractAuth<AV>>,
      ComAtprotoAdminDisableInviteCodes.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.admin.disableInviteCodes' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  enableAccountInvites<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoAdminEnableAccountInvites.Handler<ExtractAuth<AV>>,
      ComAtprotoAdminEnableAccountInvites.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.admin.enableAccountInvites' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getAccountInfo<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoAdminGetAccountInfo.Handler<ExtractAuth<AV>>,
      ComAtprotoAdminGetAccountInfo.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.admin.getAccountInfo' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getAccountInfos<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoAdminGetAccountInfos.Handler<ExtractAuth<AV>>,
      ComAtprotoAdminGetAccountInfos.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.admin.getAccountInfos' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getInviteCodes<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoAdminGetInviteCodes.Handler<ExtractAuth<AV>>,
      ComAtprotoAdminGetInviteCodes.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.admin.getInviteCodes' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getSubjectStatus<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoAdminGetSubjectStatus.Handler<ExtractAuth<AV>>,
      ComAtprotoAdminGetSubjectStatus.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.admin.getSubjectStatus' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  searchAccounts<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoAdminSearchAccounts.Handler<ExtractAuth<AV>>,
      ComAtprotoAdminSearchAccounts.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.admin.searchAccounts' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  sendEmail<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoAdminSendEmail.Handler<ExtractAuth<AV>>,
      ComAtprotoAdminSendEmail.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.admin.sendEmail' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  updateAccountEmail<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoAdminUpdateAccountEmail.Handler<ExtractAuth<AV>>,
      ComAtprotoAdminUpdateAccountEmail.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.admin.updateAccountEmail' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  updateAccountHandle<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoAdminUpdateAccountHandle.Handler<ExtractAuth<AV>>,
      ComAtprotoAdminUpdateAccountHandle.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.admin.updateAccountHandle' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  updateAccountPassword<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoAdminUpdateAccountPassword.Handler<ExtractAuth<AV>>,
      ComAtprotoAdminUpdateAccountPassword.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.admin.updateAccountPassword' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  updateAccountSigningKey<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoAdminUpdateAccountSigningKey.Handler<ExtractAuth<AV>>,
      ComAtprotoAdminUpdateAccountSigningKey.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.admin.updateAccountSigningKey' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  updateSubjectStatus<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoAdminUpdateSubjectStatus.Handler<ExtractAuth<AV>>,
      ComAtprotoAdminUpdateSubjectStatus.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.admin.updateSubjectStatus' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }
}

export class ComAtprotoIdentityNS {
  _server: Server

  constructor(server: Server) {
    this._server = server
  }

  getRecommendedDidCredentials<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoIdentityGetRecommendedDidCredentials.Handler<ExtractAuth<AV>>,
      ComAtprotoIdentityGetRecommendedDidCredentials.HandlerReqCtx<
        ExtractAuth<AV>
      >
    >,
  ) {
    const nsid = 'com.atproto.identity.getRecommendedDidCredentials' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  refreshIdentity<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoIdentityRefreshIdentity.Handler<ExtractAuth<AV>>,
      ComAtprotoIdentityRefreshIdentity.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.identity.refreshIdentity' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  requestPlcOperationSignature<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoIdentityRequestPlcOperationSignature.Handler<ExtractAuth<AV>>,
      ComAtprotoIdentityRequestPlcOperationSignature.HandlerReqCtx<
        ExtractAuth<AV>
      >
    >,
  ) {
    const nsid = 'com.atproto.identity.requestPlcOperationSignature' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  resolveDid<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoIdentityResolveDid.Handler<ExtractAuth<AV>>,
      ComAtprotoIdentityResolveDid.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.identity.resolveDid' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  resolveHandle<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoIdentityResolveHandle.Handler<ExtractAuth<AV>>,
      ComAtprotoIdentityResolveHandle.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.identity.resolveHandle' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  resolveIdentity<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoIdentityResolveIdentity.Handler<ExtractAuth<AV>>,
      ComAtprotoIdentityResolveIdentity.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.identity.resolveIdentity' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  signPlcOperation<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoIdentitySignPlcOperation.Handler<ExtractAuth<AV>>,
      ComAtprotoIdentitySignPlcOperation.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.identity.signPlcOperation' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  submitPlcOperation<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoIdentitySubmitPlcOperation.Handler<ExtractAuth<AV>>,
      ComAtprotoIdentitySubmitPlcOperation.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.identity.submitPlcOperation' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  updateHandle<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoIdentityUpdateHandle.Handler<ExtractAuth<AV>>,
      ComAtprotoIdentityUpdateHandle.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.identity.updateHandle' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }
}

export class ComAtprotoLabelNS {
  _server: Server

  constructor(server: Server) {
    this._server = server
  }

  queryLabels<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoLabelQueryLabels.Handler<ExtractAuth<AV>>,
      ComAtprotoLabelQueryLabels.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.label.queryLabels' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  subscribeLabels<AV extends StreamAuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoLabelSubscribeLabels.Handler<ExtractAuth<AV>>,
      ComAtprotoLabelSubscribeLabels.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.label.subscribeLabels' // @ts-ignore
    return this._server.xrpc.streamMethod(nsid, cfg)
  }
}

export class ComAtprotoLexiconNS {
  _server: Server

  constructor(server: Server) {
    this._server = server
  }
}

export class ComAtprotoModerationNS {
  _server: Server

  constructor(server: Server) {
    this._server = server
  }

  createReport<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoModerationCreateReport.Handler<ExtractAuth<AV>>,
      ComAtprotoModerationCreateReport.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.moderation.createReport' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }
}

export class ComAtprotoRepoNS {
  _server: Server

  constructor(server: Server) {
    this._server = server
  }

  applyWrites<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoRepoApplyWrites.Handler<ExtractAuth<AV>>,
      ComAtprotoRepoApplyWrites.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.repo.applyWrites' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  createRecord<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoRepoCreateRecord.Handler<ExtractAuth<AV>>,
      ComAtprotoRepoCreateRecord.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.repo.createRecord' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  deleteRecord<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoRepoDeleteRecord.Handler<ExtractAuth<AV>>,
      ComAtprotoRepoDeleteRecord.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.repo.deleteRecord' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  describeRepo<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoRepoDescribeRepo.Handler<ExtractAuth<AV>>,
      ComAtprotoRepoDescribeRepo.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.repo.describeRepo' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getRecord<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoRepoGetRecord.Handler<ExtractAuth<AV>>,
      ComAtprotoRepoGetRecord.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.repo.getRecord' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  importRepo<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoRepoImportRepo.Handler<ExtractAuth<AV>>,
      ComAtprotoRepoImportRepo.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.repo.importRepo' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  listMissingBlobs<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoRepoListMissingBlobs.Handler<ExtractAuth<AV>>,
      ComAtprotoRepoListMissingBlobs.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.repo.listMissingBlobs' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  listRecords<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoRepoListRecords.Handler<ExtractAuth<AV>>,
      ComAtprotoRepoListRecords.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.repo.listRecords' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  putRecord<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoRepoPutRecord.Handler<ExtractAuth<AV>>,
      ComAtprotoRepoPutRecord.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.repo.putRecord' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  uploadBlob<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoRepoUploadBlob.Handler<ExtractAuth<AV>>,
      ComAtprotoRepoUploadBlob.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.repo.uploadBlob' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }
}

export class ComAtprotoServerNS {
  _server: Server

  constructor(server: Server) {
    this._server = server
  }

  activateAccount<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoServerActivateAccount.Handler<ExtractAuth<AV>>,
      ComAtprotoServerActivateAccount.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.server.activateAccount' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  checkAccountStatus<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoServerCheckAccountStatus.Handler<ExtractAuth<AV>>,
      ComAtprotoServerCheckAccountStatus.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.server.checkAccountStatus' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  confirmEmail<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoServerConfirmEmail.Handler<ExtractAuth<AV>>,
      ComAtprotoServerConfirmEmail.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.server.confirmEmail' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  createAccount<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoServerCreateAccount.Handler<ExtractAuth<AV>>,
      ComAtprotoServerCreateAccount.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.server.createAccount' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  createAppPassword<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoServerCreateAppPassword.Handler<ExtractAuth<AV>>,
      ComAtprotoServerCreateAppPassword.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.server.createAppPassword' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  createInviteCode<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoServerCreateInviteCode.Handler<ExtractAuth<AV>>,
      ComAtprotoServerCreateInviteCode.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.server.createInviteCode' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  createInviteCodes<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoServerCreateInviteCodes.Handler<ExtractAuth<AV>>,
      ComAtprotoServerCreateInviteCodes.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.server.createInviteCodes' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  createSession<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoServerCreateSession.Handler<ExtractAuth<AV>>,
      ComAtprotoServerCreateSession.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.server.createSession' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  deactivateAccount<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoServerDeactivateAccount.Handler<ExtractAuth<AV>>,
      ComAtprotoServerDeactivateAccount.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.server.deactivateAccount' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  deleteAccount<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoServerDeleteAccount.Handler<ExtractAuth<AV>>,
      ComAtprotoServerDeleteAccount.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.server.deleteAccount' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  deleteSession<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoServerDeleteSession.Handler<ExtractAuth<AV>>,
      ComAtprotoServerDeleteSession.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.server.deleteSession' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  describeServer<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoServerDescribeServer.Handler<ExtractAuth<AV>>,
      ComAtprotoServerDescribeServer.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.server.describeServer' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getAccountInviteCodes<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoServerGetAccountInviteCodes.Handler<ExtractAuth<AV>>,
      ComAtprotoServerGetAccountInviteCodes.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.server.getAccountInviteCodes' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getServiceAuth<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoServerGetServiceAuth.Handler<ExtractAuth<AV>>,
      ComAtprotoServerGetServiceAuth.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.server.getServiceAuth' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getSession<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoServerGetSession.Handler<ExtractAuth<AV>>,
      ComAtprotoServerGetSession.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.server.getSession' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  listAppPasswords<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoServerListAppPasswords.Handler<ExtractAuth<AV>>,
      ComAtprotoServerListAppPasswords.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.server.listAppPasswords' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  refreshSession<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoServerRefreshSession.Handler<ExtractAuth<AV>>,
      ComAtprotoServerRefreshSession.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.server.refreshSession' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  requestAccountDelete<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoServerRequestAccountDelete.Handler<ExtractAuth<AV>>,
      ComAtprotoServerRequestAccountDelete.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.server.requestAccountDelete' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  requestEmailConfirmation<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoServerRequestEmailConfirmation.Handler<ExtractAuth<AV>>,
      ComAtprotoServerRequestEmailConfirmation.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.server.requestEmailConfirmation' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  requestEmailUpdate<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoServerRequestEmailUpdate.Handler<ExtractAuth<AV>>,
      ComAtprotoServerRequestEmailUpdate.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.server.requestEmailUpdate' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  requestPasswordReset<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoServerRequestPasswordReset.Handler<ExtractAuth<AV>>,
      ComAtprotoServerRequestPasswordReset.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.server.requestPasswordReset' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  reserveSigningKey<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoServerReserveSigningKey.Handler<ExtractAuth<AV>>,
      ComAtprotoServerReserveSigningKey.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.server.reserveSigningKey' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  resetPassword<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoServerResetPassword.Handler<ExtractAuth<AV>>,
      ComAtprotoServerResetPassword.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.server.resetPassword' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  revokeAppPassword<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoServerRevokeAppPassword.Handler<ExtractAuth<AV>>,
      ComAtprotoServerRevokeAppPassword.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.server.revokeAppPassword' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  updateEmail<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoServerUpdateEmail.Handler<ExtractAuth<AV>>,
      ComAtprotoServerUpdateEmail.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.server.updateEmail' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }
}

export class ComAtprotoSyncNS {
  _server: Server

  constructor(server: Server) {
    this._server = server
  }

  getBlob<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoSyncGetBlob.Handler<ExtractAuth<AV>>,
      ComAtprotoSyncGetBlob.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.sync.getBlob' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getBlocks<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoSyncGetBlocks.Handler<ExtractAuth<AV>>,
      ComAtprotoSyncGetBlocks.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.sync.getBlocks' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getCheckout<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoSyncGetCheckout.Handler<ExtractAuth<AV>>,
      ComAtprotoSyncGetCheckout.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.sync.getCheckout' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getHead<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoSyncGetHead.Handler<ExtractAuth<AV>>,
      ComAtprotoSyncGetHead.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.sync.getHead' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getHostStatus<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoSyncGetHostStatus.Handler<ExtractAuth<AV>>,
      ComAtprotoSyncGetHostStatus.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.sync.getHostStatus' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getLatestCommit<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoSyncGetLatestCommit.Handler<ExtractAuth<AV>>,
      ComAtprotoSyncGetLatestCommit.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.sync.getLatestCommit' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getRecord<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoSyncGetRecord.Handler<ExtractAuth<AV>>,
      ComAtprotoSyncGetRecord.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.sync.getRecord' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getRepo<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoSyncGetRepo.Handler<ExtractAuth<AV>>,
      ComAtprotoSyncGetRepo.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.sync.getRepo' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getRepoStatus<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoSyncGetRepoStatus.Handler<ExtractAuth<AV>>,
      ComAtprotoSyncGetRepoStatus.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.sync.getRepoStatus' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  listBlobs<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoSyncListBlobs.Handler<ExtractAuth<AV>>,
      ComAtprotoSyncListBlobs.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.sync.listBlobs' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  listHosts<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoSyncListHosts.Handler<ExtractAuth<AV>>,
      ComAtprotoSyncListHosts.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.sync.listHosts' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  listRepos<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoSyncListRepos.Handler<ExtractAuth<AV>>,
      ComAtprotoSyncListRepos.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.sync.listRepos' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  listReposByCollection<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoSyncListReposByCollection.Handler<ExtractAuth<AV>>,
      ComAtprotoSyncListReposByCollection.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.sync.listReposByCollection' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  notifyOfUpdate<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoSyncNotifyOfUpdate.Handler<ExtractAuth<AV>>,
      ComAtprotoSyncNotifyOfUpdate.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.sync.notifyOfUpdate' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  requestCrawl<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoSyncRequestCrawl.Handler<ExtractAuth<AV>>,
      ComAtprotoSyncRequestCrawl.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.sync.requestCrawl' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  subscribeRepos<AV extends StreamAuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoSyncSubscribeRepos.Handler<ExtractAuth<AV>>,
      ComAtprotoSyncSubscribeRepos.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.sync.subscribeRepos' // @ts-ignore
    return this._server.xrpc.streamMethod(nsid, cfg)
  }
}

export class ComAtprotoTempNS {
  _server: Server

  constructor(server: Server) {
    this._server = server
  }

  addReservedHandle<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoTempAddReservedHandle.Handler<ExtractAuth<AV>>,
      ComAtprotoTempAddReservedHandle.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.temp.addReservedHandle' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  checkSignupQueue<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoTempCheckSignupQueue.Handler<ExtractAuth<AV>>,
      ComAtprotoTempCheckSignupQueue.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.temp.checkSignupQueue' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  fetchLabels<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoTempFetchLabels.Handler<ExtractAuth<AV>>,
      ComAtprotoTempFetchLabels.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.temp.fetchLabels' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  requestPhoneVerification<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ComAtprotoTempRequestPhoneVerification.Handler<ExtractAuth<AV>>,
      ComAtprotoTempRequestPhoneVerification.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'com.atproto.temp.requestPhoneVerification' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }
}

export class AppNS {
  _server: Server
  bsky: AppBskyNS

  constructor(server: Server) {
    this._server = server
    this.bsky = new AppBskyNS(server)
  }
}

export class AppBskyNS {
  _server: Server
  actor: AppBskyActorNS
  embed: AppBskyEmbedNS
  feed: AppBskyFeedNS
  graph: AppBskyGraphNS
  labeler: AppBskyLabelerNS
  notification: AppBskyNotificationNS
  richtext: AppBskyRichtextNS
  sources: AppBskySourcesNS
  unspecced: AppBskyUnspeccedNS
  video: AppBskyVideoNS

  constructor(server: Server) {
    this._server = server
    this.actor = new AppBskyActorNS(server)
    this.embed = new AppBskyEmbedNS(server)
    this.feed = new AppBskyFeedNS(server)
    this.graph = new AppBskyGraphNS(server)
    this.labeler = new AppBskyLabelerNS(server)
    this.notification = new AppBskyNotificationNS(server)
    this.richtext = new AppBskyRichtextNS(server)
    this.sources = new AppBskySourcesNS(server)
    this.unspecced = new AppBskyUnspeccedNS(server)
    this.video = new AppBskyVideoNS(server)
  }
}

export class AppBskyActorNS {
  _server: Server

  constructor(server: Server) {
    this._server = server
  }

  getPreferences<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyActorGetPreferences.Handler<ExtractAuth<AV>>,
      AppBskyActorGetPreferences.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.actor.getPreferences' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getProfile<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyActorGetProfile.Handler<ExtractAuth<AV>>,
      AppBskyActorGetProfile.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.actor.getProfile' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getProfiles<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyActorGetProfiles.Handler<ExtractAuth<AV>>,
      AppBskyActorGetProfiles.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.actor.getProfiles' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getSuggestions<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyActorGetSuggestions.Handler<ExtractAuth<AV>>,
      AppBskyActorGetSuggestions.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.actor.getSuggestions' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  putPreferences<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyActorPutPreferences.Handler<ExtractAuth<AV>>,
      AppBskyActorPutPreferences.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.actor.putPreferences' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  searchActors<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyActorSearchActors.Handler<ExtractAuth<AV>>,
      AppBskyActorSearchActors.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.actor.searchActors' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  searchActorsTypeahead<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyActorSearchActorsTypeahead.Handler<ExtractAuth<AV>>,
      AppBskyActorSearchActorsTypeahead.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.actor.searchActorsTypeahead' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }
}

export class AppBskyEmbedNS {
  _server: Server

  constructor(server: Server) {
    this._server = server
  }
}

export class AppBskyFeedNS {
  _server: Server

  constructor(server: Server) {
    this._server = server
  }

  describeFeedGenerator<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyFeedDescribeFeedGenerator.Handler<ExtractAuth<AV>>,
      AppBskyFeedDescribeFeedGenerator.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.feed.describeFeedGenerator' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getActorFeeds<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyFeedGetActorFeeds.Handler<ExtractAuth<AV>>,
      AppBskyFeedGetActorFeeds.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.feed.getActorFeeds' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getActorLikes<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyFeedGetActorLikes.Handler<ExtractAuth<AV>>,
      AppBskyFeedGetActorLikes.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.feed.getActorLikes' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getAuthorFeed<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyFeedGetAuthorFeed.Handler<ExtractAuth<AV>>,
      AppBskyFeedGetAuthorFeed.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.feed.getAuthorFeed' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getFeed<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyFeedGetFeed.Handler<ExtractAuth<AV>>,
      AppBskyFeedGetFeed.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.feed.getFeed' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getFeedGenerator<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyFeedGetFeedGenerator.Handler<ExtractAuth<AV>>,
      AppBskyFeedGetFeedGenerator.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.feed.getFeedGenerator' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getFeedGenerators<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyFeedGetFeedGenerators.Handler<ExtractAuth<AV>>,
      AppBskyFeedGetFeedGenerators.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.feed.getFeedGenerators' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getFeedSkeleton<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyFeedGetFeedSkeleton.Handler<ExtractAuth<AV>>,
      AppBskyFeedGetFeedSkeleton.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.feed.getFeedSkeleton' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getLikes<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyFeedGetLikes.Handler<ExtractAuth<AV>>,
      AppBskyFeedGetLikes.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.feed.getLikes' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getListFeed<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyFeedGetListFeed.Handler<ExtractAuth<AV>>,
      AppBskyFeedGetListFeed.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.feed.getListFeed' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getPostThread<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyFeedGetPostThread.Handler<ExtractAuth<AV>>,
      AppBskyFeedGetPostThread.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.feed.getPostThread' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getPosts<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyFeedGetPosts.Handler<ExtractAuth<AV>>,
      AppBskyFeedGetPosts.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.feed.getPosts' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getQuotes<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyFeedGetQuotes.Handler<ExtractAuth<AV>>,
      AppBskyFeedGetQuotes.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.feed.getQuotes' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getRepostedBy<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyFeedGetRepostedBy.Handler<ExtractAuth<AV>>,
      AppBskyFeedGetRepostedBy.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.feed.getRepostedBy' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getSuggestedFeeds<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyFeedGetSuggestedFeeds.Handler<ExtractAuth<AV>>,
      AppBskyFeedGetSuggestedFeeds.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.feed.getSuggestedFeeds' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getTimeline<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyFeedGetTimeline.Handler<ExtractAuth<AV>>,
      AppBskyFeedGetTimeline.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.feed.getTimeline' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  searchPosts<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyFeedSearchPosts.Handler<ExtractAuth<AV>>,
      AppBskyFeedSearchPosts.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.feed.searchPosts' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  sendInteractions<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyFeedSendInteractions.Handler<ExtractAuth<AV>>,
      AppBskyFeedSendInteractions.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.feed.sendInteractions' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }
}

export class AppBskyGraphNS {
  _server: Server

  constructor(server: Server) {
    this._server = server
  }

  getActorStarterPacks<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyGraphGetActorStarterPacks.Handler<ExtractAuth<AV>>,
      AppBskyGraphGetActorStarterPacks.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.graph.getActorStarterPacks' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getBlocks<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyGraphGetBlocks.Handler<ExtractAuth<AV>>,
      AppBskyGraphGetBlocks.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.graph.getBlocks' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getFollowers<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyGraphGetFollowers.Handler<ExtractAuth<AV>>,
      AppBskyGraphGetFollowers.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.graph.getFollowers' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getFollows<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyGraphGetFollows.Handler<ExtractAuth<AV>>,
      AppBskyGraphGetFollows.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.graph.getFollows' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getKnownFollowers<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyGraphGetKnownFollowers.Handler<ExtractAuth<AV>>,
      AppBskyGraphGetKnownFollowers.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.graph.getKnownFollowers' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getList<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyGraphGetList.Handler<ExtractAuth<AV>>,
      AppBskyGraphGetList.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.graph.getList' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getListBlocks<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyGraphGetListBlocks.Handler<ExtractAuth<AV>>,
      AppBskyGraphGetListBlocks.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.graph.getListBlocks' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getListMutes<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyGraphGetListMutes.Handler<ExtractAuth<AV>>,
      AppBskyGraphGetListMutes.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.graph.getListMutes' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getLists<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyGraphGetLists.Handler<ExtractAuth<AV>>,
      AppBskyGraphGetLists.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.graph.getLists' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getMutes<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyGraphGetMutes.Handler<ExtractAuth<AV>>,
      AppBskyGraphGetMutes.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.graph.getMutes' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getRelationships<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyGraphGetRelationships.Handler<ExtractAuth<AV>>,
      AppBskyGraphGetRelationships.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.graph.getRelationships' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getStarterPack<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyGraphGetStarterPack.Handler<ExtractAuth<AV>>,
      AppBskyGraphGetStarterPack.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.graph.getStarterPack' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getStarterPacks<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyGraphGetStarterPacks.Handler<ExtractAuth<AV>>,
      AppBskyGraphGetStarterPacks.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.graph.getStarterPacks' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getSuggestedFollowsByActor<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyGraphGetSuggestedFollowsByActor.Handler<ExtractAuth<AV>>,
      AppBskyGraphGetSuggestedFollowsByActor.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.graph.getSuggestedFollowsByActor' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  muteActor<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyGraphMuteActor.Handler<ExtractAuth<AV>>,
      AppBskyGraphMuteActor.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.graph.muteActor' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  muteActorList<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyGraphMuteActorList.Handler<ExtractAuth<AV>>,
      AppBskyGraphMuteActorList.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.graph.muteActorList' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  muteThread<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyGraphMuteThread.Handler<ExtractAuth<AV>>,
      AppBskyGraphMuteThread.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.graph.muteThread' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  searchStarterPacks<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyGraphSearchStarterPacks.Handler<ExtractAuth<AV>>,
      AppBskyGraphSearchStarterPacks.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.graph.searchStarterPacks' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  unmuteActor<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyGraphUnmuteActor.Handler<ExtractAuth<AV>>,
      AppBskyGraphUnmuteActor.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.graph.unmuteActor' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  unmuteActorList<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyGraphUnmuteActorList.Handler<ExtractAuth<AV>>,
      AppBskyGraphUnmuteActorList.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.graph.unmuteActorList' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  unmuteThread<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyGraphUnmuteThread.Handler<ExtractAuth<AV>>,
      AppBskyGraphUnmuteThread.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.graph.unmuteThread' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }
}

export class AppBskyLabelerNS {
  _server: Server

  constructor(server: Server) {
    this._server = server
  }

  getServices<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyLabelerGetServices.Handler<ExtractAuth<AV>>,
      AppBskyLabelerGetServices.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.labeler.getServices' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }
}

export class AppBskyNotificationNS {
  _server: Server

  constructor(server: Server) {
    this._server = server
  }

  getPreferences<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyNotificationGetPreferences.Handler<ExtractAuth<AV>>,
      AppBskyNotificationGetPreferences.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.notification.getPreferences' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getUnreadCount<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyNotificationGetUnreadCount.Handler<ExtractAuth<AV>>,
      AppBskyNotificationGetUnreadCount.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.notification.getUnreadCount' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  listActivitySubscriptions<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyNotificationListActivitySubscriptions.Handler<ExtractAuth<AV>>,
      AppBskyNotificationListActivitySubscriptions.HandlerReqCtx<
        ExtractAuth<AV>
      >
    >,
  ) {
    const nsid = 'app.bsky.notification.listActivitySubscriptions' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  listNotifications<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyNotificationListNotifications.Handler<ExtractAuth<AV>>,
      AppBskyNotificationListNotifications.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.notification.listNotifications' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  putActivitySubscription<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyNotificationPutActivitySubscription.Handler<ExtractAuth<AV>>,
      AppBskyNotificationPutActivitySubscription.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.notification.putActivitySubscription' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  putPreferences<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyNotificationPutPreferences.Handler<ExtractAuth<AV>>,
      AppBskyNotificationPutPreferences.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.notification.putPreferences' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  putPreferencesV2<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyNotificationPutPreferencesV2.Handler<ExtractAuth<AV>>,
      AppBskyNotificationPutPreferencesV2.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.notification.putPreferencesV2' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  registerPush<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyNotificationRegisterPush.Handler<ExtractAuth<AV>>,
      AppBskyNotificationRegisterPush.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.notification.registerPush' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  updateSeen<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyNotificationUpdateSeen.Handler<ExtractAuth<AV>>,
      AppBskyNotificationUpdateSeen.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.notification.updateSeen' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }
}

export class AppBskyRichtextNS {
  _server: Server

  constructor(server: Server) {
    this._server = server
  }
}

export class AppBskySourcesNS {
  _server: Server

  constructor(server: Server) {
    this._server = server
  }

  addComment<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskySourcesAddComment.Handler<ExtractAuth<AV>>,
      AppBskySourcesAddComment.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.sources.addComment' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  create<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskySourcesCreate.Handler<ExtractAuth<AV>>,
      AppBskySourcesCreate.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.sources.create' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  get<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskySourcesGet.Handler<ExtractAuth<AV>>,
      AppBskySourcesGet.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.sources.get' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getComments<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskySourcesGetComments.Handler<ExtractAuth<AV>>,
      AppBskySourcesGetComments.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.sources.getComments' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  list<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskySourcesList.Handler<ExtractAuth<AV>>,
      AppBskySourcesList.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.sources.list' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  vote<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskySourcesVote.Handler<ExtractAuth<AV>>,
      AppBskySourcesVote.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.sources.vote' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }
}

export class AppBskyUnspeccedNS {
  _server: Server

  constructor(server: Server) {
    this._server = server
  }

  getConfig<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyUnspeccedGetConfig.Handler<ExtractAuth<AV>>,
      AppBskyUnspeccedGetConfig.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.unspecced.getConfig' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getPopularFeedGenerators<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyUnspeccedGetPopularFeedGenerators.Handler<ExtractAuth<AV>>,
      AppBskyUnspeccedGetPopularFeedGenerators.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.unspecced.getPopularFeedGenerators' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getPostThreadOtherV2<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyUnspeccedGetPostThreadOtherV2.Handler<ExtractAuth<AV>>,
      AppBskyUnspeccedGetPostThreadOtherV2.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.unspecced.getPostThreadOtherV2' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getPostThreadV2<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyUnspeccedGetPostThreadV2.Handler<ExtractAuth<AV>>,
      AppBskyUnspeccedGetPostThreadV2.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.unspecced.getPostThreadV2' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getSuggestedFeeds<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyUnspeccedGetSuggestedFeeds.Handler<ExtractAuth<AV>>,
      AppBskyUnspeccedGetSuggestedFeeds.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.unspecced.getSuggestedFeeds' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getSuggestedFeedsSkeleton<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyUnspeccedGetSuggestedFeedsSkeleton.Handler<ExtractAuth<AV>>,
      AppBskyUnspeccedGetSuggestedFeedsSkeleton.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.unspecced.getSuggestedFeedsSkeleton' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getSuggestedStarterPacks<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyUnspeccedGetSuggestedStarterPacks.Handler<ExtractAuth<AV>>,
      AppBskyUnspeccedGetSuggestedStarterPacks.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.unspecced.getSuggestedStarterPacks' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getSuggestedStarterPacksSkeleton<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyUnspeccedGetSuggestedStarterPacksSkeleton.Handler<ExtractAuth<AV>>,
      AppBskyUnspeccedGetSuggestedStarterPacksSkeleton.HandlerReqCtx<
        ExtractAuth<AV>
      >
    >,
  ) {
    const nsid = 'app.bsky.unspecced.getSuggestedStarterPacksSkeleton' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getSuggestedUsers<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyUnspeccedGetSuggestedUsers.Handler<ExtractAuth<AV>>,
      AppBskyUnspeccedGetSuggestedUsers.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.unspecced.getSuggestedUsers' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getSuggestedUsersSkeleton<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyUnspeccedGetSuggestedUsersSkeleton.Handler<ExtractAuth<AV>>,
      AppBskyUnspeccedGetSuggestedUsersSkeleton.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.unspecced.getSuggestedUsersSkeleton' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getSuggestionsSkeleton<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyUnspeccedGetSuggestionsSkeleton.Handler<ExtractAuth<AV>>,
      AppBskyUnspeccedGetSuggestionsSkeleton.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.unspecced.getSuggestionsSkeleton' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getTaggedSuggestions<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyUnspeccedGetTaggedSuggestions.Handler<ExtractAuth<AV>>,
      AppBskyUnspeccedGetTaggedSuggestions.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.unspecced.getTaggedSuggestions' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getTrendingTopics<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyUnspeccedGetTrendingTopics.Handler<ExtractAuth<AV>>,
      AppBskyUnspeccedGetTrendingTopics.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.unspecced.getTrendingTopics' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getTrends<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyUnspeccedGetTrends.Handler<ExtractAuth<AV>>,
      AppBskyUnspeccedGetTrends.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.unspecced.getTrends' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getTrendsSkeleton<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyUnspeccedGetTrendsSkeleton.Handler<ExtractAuth<AV>>,
      AppBskyUnspeccedGetTrendsSkeleton.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.unspecced.getTrendsSkeleton' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  searchActorsSkeleton<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyUnspeccedSearchActorsSkeleton.Handler<ExtractAuth<AV>>,
      AppBskyUnspeccedSearchActorsSkeleton.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.unspecced.searchActorsSkeleton' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  searchPostsSkeleton<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyUnspeccedSearchPostsSkeleton.Handler<ExtractAuth<AV>>,
      AppBskyUnspeccedSearchPostsSkeleton.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.unspecced.searchPostsSkeleton' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  searchStarterPacksSkeleton<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyUnspeccedSearchStarterPacksSkeleton.Handler<ExtractAuth<AV>>,
      AppBskyUnspeccedSearchStarterPacksSkeleton.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.unspecced.searchStarterPacksSkeleton' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }
}

export class AppBskyVideoNS {
  _server: Server

  constructor(server: Server) {
    this._server = server
  }

  getJobStatus<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyVideoGetJobStatus.Handler<ExtractAuth<AV>>,
      AppBskyVideoGetJobStatus.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.video.getJobStatus' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getUploadLimits<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyVideoGetUploadLimits.Handler<ExtractAuth<AV>>,
      AppBskyVideoGetUploadLimits.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.video.getUploadLimits' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  uploadVideo<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      AppBskyVideoUploadVideo.Handler<ExtractAuth<AV>>,
      AppBskyVideoUploadVideo.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'app.bsky.video.uploadVideo' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }
}

export class ChatNS {
  _server: Server
  bsky: ChatBskyNS

  constructor(server: Server) {
    this._server = server
    this.bsky = new ChatBskyNS(server)
  }
}

export class ChatBskyNS {
  _server: Server
  actor: ChatBskyActorNS
  convo: ChatBskyConvoNS
  moderation: ChatBskyModerationNS

  constructor(server: Server) {
    this._server = server
    this.actor = new ChatBskyActorNS(server)
    this.convo = new ChatBskyConvoNS(server)
    this.moderation = new ChatBskyModerationNS(server)
  }
}

export class ChatBskyActorNS {
  _server: Server

  constructor(server: Server) {
    this._server = server
  }

  deleteAccount<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ChatBskyActorDeleteAccount.Handler<ExtractAuth<AV>>,
      ChatBskyActorDeleteAccount.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'chat.bsky.actor.deleteAccount' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  exportAccountData<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ChatBskyActorExportAccountData.Handler<ExtractAuth<AV>>,
      ChatBskyActorExportAccountData.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'chat.bsky.actor.exportAccountData' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }
}

export class ChatBskyConvoNS {
  _server: Server

  constructor(server: Server) {
    this._server = server
  }

  acceptConvo<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ChatBskyConvoAcceptConvo.Handler<ExtractAuth<AV>>,
      ChatBskyConvoAcceptConvo.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'chat.bsky.convo.acceptConvo' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  addReaction<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ChatBskyConvoAddReaction.Handler<ExtractAuth<AV>>,
      ChatBskyConvoAddReaction.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'chat.bsky.convo.addReaction' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  deleteMessageForSelf<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ChatBskyConvoDeleteMessageForSelf.Handler<ExtractAuth<AV>>,
      ChatBskyConvoDeleteMessageForSelf.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'chat.bsky.convo.deleteMessageForSelf' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getConvo<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ChatBskyConvoGetConvo.Handler<ExtractAuth<AV>>,
      ChatBskyConvoGetConvo.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'chat.bsky.convo.getConvo' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getConvoAvailability<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ChatBskyConvoGetConvoAvailability.Handler<ExtractAuth<AV>>,
      ChatBskyConvoGetConvoAvailability.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'chat.bsky.convo.getConvoAvailability' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getConvoForMembers<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ChatBskyConvoGetConvoForMembers.Handler<ExtractAuth<AV>>,
      ChatBskyConvoGetConvoForMembers.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'chat.bsky.convo.getConvoForMembers' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getLog<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ChatBskyConvoGetLog.Handler<ExtractAuth<AV>>,
      ChatBskyConvoGetLog.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'chat.bsky.convo.getLog' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getMessages<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ChatBskyConvoGetMessages.Handler<ExtractAuth<AV>>,
      ChatBskyConvoGetMessages.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'chat.bsky.convo.getMessages' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  leaveConvo<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ChatBskyConvoLeaveConvo.Handler<ExtractAuth<AV>>,
      ChatBskyConvoLeaveConvo.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'chat.bsky.convo.leaveConvo' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  listConvos<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ChatBskyConvoListConvos.Handler<ExtractAuth<AV>>,
      ChatBskyConvoListConvos.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'chat.bsky.convo.listConvos' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  muteConvo<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ChatBskyConvoMuteConvo.Handler<ExtractAuth<AV>>,
      ChatBskyConvoMuteConvo.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'chat.bsky.convo.muteConvo' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  removeReaction<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ChatBskyConvoRemoveReaction.Handler<ExtractAuth<AV>>,
      ChatBskyConvoRemoveReaction.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'chat.bsky.convo.removeReaction' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  sendMessage<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ChatBskyConvoSendMessage.Handler<ExtractAuth<AV>>,
      ChatBskyConvoSendMessage.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'chat.bsky.convo.sendMessage' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  sendMessageBatch<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ChatBskyConvoSendMessageBatch.Handler<ExtractAuth<AV>>,
      ChatBskyConvoSendMessageBatch.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'chat.bsky.convo.sendMessageBatch' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  unmuteConvo<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ChatBskyConvoUnmuteConvo.Handler<ExtractAuth<AV>>,
      ChatBskyConvoUnmuteConvo.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'chat.bsky.convo.unmuteConvo' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  updateAllRead<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ChatBskyConvoUpdateAllRead.Handler<ExtractAuth<AV>>,
      ChatBskyConvoUpdateAllRead.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'chat.bsky.convo.updateAllRead' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  updateRead<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ChatBskyConvoUpdateRead.Handler<ExtractAuth<AV>>,
      ChatBskyConvoUpdateRead.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'chat.bsky.convo.updateRead' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }
}

export class ChatBskyModerationNS {
  _server: Server

  constructor(server: Server) {
    this._server = server
  }

  getActorMetadata<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ChatBskyModerationGetActorMetadata.Handler<ExtractAuth<AV>>,
      ChatBskyModerationGetActorMetadata.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'chat.bsky.moderation.getActorMetadata' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getMessageContext<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ChatBskyModerationGetMessageContext.Handler<ExtractAuth<AV>>,
      ChatBskyModerationGetMessageContext.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'chat.bsky.moderation.getMessageContext' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  updateActorAccess<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ChatBskyModerationUpdateActorAccess.Handler<ExtractAuth<AV>>,
      ChatBskyModerationUpdateActorAccess.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'chat.bsky.moderation.updateActorAccess' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }
}

export class ToolsNS {
  _server: Server
  ozone: ToolsOzoneNS

  constructor(server: Server) {
    this._server = server
    this.ozone = new ToolsOzoneNS(server)
  }
}

export class ToolsOzoneNS {
  _server: Server
  communication: ToolsOzoneCommunicationNS
  hosting: ToolsOzoneHostingNS
  moderation: ToolsOzoneModerationNS
  server: ToolsOzoneServerNS
  set: ToolsOzoneSetNS
  setting: ToolsOzoneSettingNS
  signature: ToolsOzoneSignatureNS
  team: ToolsOzoneTeamNS
  verification: ToolsOzoneVerificationNS

  constructor(server: Server) {
    this._server = server
    this.communication = new ToolsOzoneCommunicationNS(server)
    this.hosting = new ToolsOzoneHostingNS(server)
    this.moderation = new ToolsOzoneModerationNS(server)
    this.server = new ToolsOzoneServerNS(server)
    this.set = new ToolsOzoneSetNS(server)
    this.setting = new ToolsOzoneSettingNS(server)
    this.signature = new ToolsOzoneSignatureNS(server)
    this.team = new ToolsOzoneTeamNS(server)
    this.verification = new ToolsOzoneVerificationNS(server)
  }
}

export class ToolsOzoneCommunicationNS {
  _server: Server

  constructor(server: Server) {
    this._server = server
  }

  createTemplate<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ToolsOzoneCommunicationCreateTemplate.Handler<ExtractAuth<AV>>,
      ToolsOzoneCommunicationCreateTemplate.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'tools.ozone.communication.createTemplate' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  deleteTemplate<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ToolsOzoneCommunicationDeleteTemplate.Handler<ExtractAuth<AV>>,
      ToolsOzoneCommunicationDeleteTemplate.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'tools.ozone.communication.deleteTemplate' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  listTemplates<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ToolsOzoneCommunicationListTemplates.Handler<ExtractAuth<AV>>,
      ToolsOzoneCommunicationListTemplates.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'tools.ozone.communication.listTemplates' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  updateTemplate<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ToolsOzoneCommunicationUpdateTemplate.Handler<ExtractAuth<AV>>,
      ToolsOzoneCommunicationUpdateTemplate.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'tools.ozone.communication.updateTemplate' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }
}

export class ToolsOzoneHostingNS {
  _server: Server

  constructor(server: Server) {
    this._server = server
  }

  getAccountHistory<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ToolsOzoneHostingGetAccountHistory.Handler<ExtractAuth<AV>>,
      ToolsOzoneHostingGetAccountHistory.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'tools.ozone.hosting.getAccountHistory' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }
}

export class ToolsOzoneModerationNS {
  _server: Server

  constructor(server: Server) {
    this._server = server
  }

  emitEvent<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ToolsOzoneModerationEmitEvent.Handler<ExtractAuth<AV>>,
      ToolsOzoneModerationEmitEvent.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'tools.ozone.moderation.emitEvent' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getEvent<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ToolsOzoneModerationGetEvent.Handler<ExtractAuth<AV>>,
      ToolsOzoneModerationGetEvent.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'tools.ozone.moderation.getEvent' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getRecord<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ToolsOzoneModerationGetRecord.Handler<ExtractAuth<AV>>,
      ToolsOzoneModerationGetRecord.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'tools.ozone.moderation.getRecord' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getRecords<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ToolsOzoneModerationGetRecords.Handler<ExtractAuth<AV>>,
      ToolsOzoneModerationGetRecords.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'tools.ozone.moderation.getRecords' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getRepo<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ToolsOzoneModerationGetRepo.Handler<ExtractAuth<AV>>,
      ToolsOzoneModerationGetRepo.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'tools.ozone.moderation.getRepo' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getReporterStats<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ToolsOzoneModerationGetReporterStats.Handler<ExtractAuth<AV>>,
      ToolsOzoneModerationGetReporterStats.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'tools.ozone.moderation.getReporterStats' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getRepos<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ToolsOzoneModerationGetRepos.Handler<ExtractAuth<AV>>,
      ToolsOzoneModerationGetRepos.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'tools.ozone.moderation.getRepos' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getSubjects<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ToolsOzoneModerationGetSubjects.Handler<ExtractAuth<AV>>,
      ToolsOzoneModerationGetSubjects.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'tools.ozone.moderation.getSubjects' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  queryEvents<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ToolsOzoneModerationQueryEvents.Handler<ExtractAuth<AV>>,
      ToolsOzoneModerationQueryEvents.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'tools.ozone.moderation.queryEvents' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  queryStatuses<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ToolsOzoneModerationQueryStatuses.Handler<ExtractAuth<AV>>,
      ToolsOzoneModerationQueryStatuses.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'tools.ozone.moderation.queryStatuses' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  searchRepos<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ToolsOzoneModerationSearchRepos.Handler<ExtractAuth<AV>>,
      ToolsOzoneModerationSearchRepos.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'tools.ozone.moderation.searchRepos' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }
}

export class ToolsOzoneServerNS {
  _server: Server

  constructor(server: Server) {
    this._server = server
  }

  getConfig<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ToolsOzoneServerGetConfig.Handler<ExtractAuth<AV>>,
      ToolsOzoneServerGetConfig.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'tools.ozone.server.getConfig' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }
}

export class ToolsOzoneSetNS {
  _server: Server

  constructor(server: Server) {
    this._server = server
  }

  addValues<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ToolsOzoneSetAddValues.Handler<ExtractAuth<AV>>,
      ToolsOzoneSetAddValues.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'tools.ozone.set.addValues' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  deleteSet<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ToolsOzoneSetDeleteSet.Handler<ExtractAuth<AV>>,
      ToolsOzoneSetDeleteSet.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'tools.ozone.set.deleteSet' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  deleteValues<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ToolsOzoneSetDeleteValues.Handler<ExtractAuth<AV>>,
      ToolsOzoneSetDeleteValues.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'tools.ozone.set.deleteValues' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  getValues<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ToolsOzoneSetGetValues.Handler<ExtractAuth<AV>>,
      ToolsOzoneSetGetValues.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'tools.ozone.set.getValues' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  querySets<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ToolsOzoneSetQuerySets.Handler<ExtractAuth<AV>>,
      ToolsOzoneSetQuerySets.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'tools.ozone.set.querySets' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  upsertSet<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ToolsOzoneSetUpsertSet.Handler<ExtractAuth<AV>>,
      ToolsOzoneSetUpsertSet.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'tools.ozone.set.upsertSet' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }
}

export class ToolsOzoneSettingNS {
  _server: Server

  constructor(server: Server) {
    this._server = server
  }

  listOptions<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ToolsOzoneSettingListOptions.Handler<ExtractAuth<AV>>,
      ToolsOzoneSettingListOptions.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'tools.ozone.setting.listOptions' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  removeOptions<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ToolsOzoneSettingRemoveOptions.Handler<ExtractAuth<AV>>,
      ToolsOzoneSettingRemoveOptions.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'tools.ozone.setting.removeOptions' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  upsertOption<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ToolsOzoneSettingUpsertOption.Handler<ExtractAuth<AV>>,
      ToolsOzoneSettingUpsertOption.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'tools.ozone.setting.upsertOption' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }
}

export class ToolsOzoneSignatureNS {
  _server: Server

  constructor(server: Server) {
    this._server = server
  }

  findCorrelation<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ToolsOzoneSignatureFindCorrelation.Handler<ExtractAuth<AV>>,
      ToolsOzoneSignatureFindCorrelation.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'tools.ozone.signature.findCorrelation' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  findRelatedAccounts<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ToolsOzoneSignatureFindRelatedAccounts.Handler<ExtractAuth<AV>>,
      ToolsOzoneSignatureFindRelatedAccounts.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'tools.ozone.signature.findRelatedAccounts' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  searchAccounts<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ToolsOzoneSignatureSearchAccounts.Handler<ExtractAuth<AV>>,
      ToolsOzoneSignatureSearchAccounts.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'tools.ozone.signature.searchAccounts' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }
}

export class ToolsOzoneTeamNS {
  _server: Server

  constructor(server: Server) {
    this._server = server
  }

  addMember<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ToolsOzoneTeamAddMember.Handler<ExtractAuth<AV>>,
      ToolsOzoneTeamAddMember.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'tools.ozone.team.addMember' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  deleteMember<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ToolsOzoneTeamDeleteMember.Handler<ExtractAuth<AV>>,
      ToolsOzoneTeamDeleteMember.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'tools.ozone.team.deleteMember' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  listMembers<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ToolsOzoneTeamListMembers.Handler<ExtractAuth<AV>>,
      ToolsOzoneTeamListMembers.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'tools.ozone.team.listMembers' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  updateMember<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ToolsOzoneTeamUpdateMember.Handler<ExtractAuth<AV>>,
      ToolsOzoneTeamUpdateMember.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'tools.ozone.team.updateMember' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }
}

export class ToolsOzoneVerificationNS {
  _server: Server

  constructor(server: Server) {
    this._server = server
  }

  grantVerifications<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ToolsOzoneVerificationGrantVerifications.Handler<ExtractAuth<AV>>,
      ToolsOzoneVerificationGrantVerifications.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'tools.ozone.verification.grantVerifications' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  listVerifications<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ToolsOzoneVerificationListVerifications.Handler<ExtractAuth<AV>>,
      ToolsOzoneVerificationListVerifications.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'tools.ozone.verification.listVerifications' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }

  revokeVerifications<AV extends AuthVerifier>(
    cfg: ConfigOf<
      AV,
      ToolsOzoneVerificationRevokeVerifications.Handler<ExtractAuth<AV>>,
      ToolsOzoneVerificationRevokeVerifications.HandlerReqCtx<ExtractAuth<AV>>
    >,
  ) {
    const nsid = 'tools.ozone.verification.revokeVerifications' // @ts-ignore
    return this._server.xrpc.method(nsid, cfg)
  }
}

type SharedRateLimitOpts<T> = {
  name: string
  calcKey?: (ctx: T) => string | null
  calcPoints?: (ctx: T) => number
}
type RouteRateLimitOpts<T> = {
  durationMs: number
  points: number
  calcKey?: (ctx: T) => string | null
  calcPoints?: (ctx: T) => number
}
type HandlerOpts = { blobLimit?: number }
type HandlerRateLimitOpts<T> = SharedRateLimitOpts<T> | RouteRateLimitOpts<T>
type ConfigOf<Auth, Handler, ReqCtx> =
  | Handler
  | {
      auth?: Auth
      opts?: HandlerOpts
      rateLimit?: HandlerRateLimitOpts<ReqCtx> | HandlerRateLimitOpts<ReqCtx>[]
      handler: Handler
    }
type ExtractAuth<AV extends AuthVerifier | StreamAuthVerifier> = Extract<
  Awaited<ReturnType<AV>>,
  { credentials: unknown }
>
