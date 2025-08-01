import * as account from './account'
import * as accountDevice from './account-device'
import * as actor from './actor'
import * as appPassword from './app-password'
import * as oauthRequest from './authorization-request'
import * as authorizedClient from './authorized-client'
import * as device from './device'
import * as emailToken from './email-token'
import * as inviteCode from './invite-code'
import * as refreshToken from './refresh-token'
import * as repoRoot from './repo-root'
import * as sources from './sources'
import * as sourceVotes from './source-votes'
import * as token from './token'
import * as usedRefreshToken from './used-refresh-token'

export type DatabaseSchema = actor.PartialDB &
  account.PartialDB &
  accountDevice.PartialDB &
  authorizedClient.PartialDB &
  device.PartialDB &
  oauthRequest.PartialDB &
  token.PartialDB &
  usedRefreshToken.PartialDB &
  refreshToken.PartialDB &
  appPassword.PartialDB &
  repoRoot.PartialDB &
  inviteCode.PartialDB &
  emailToken.PartialDB &
  sources.PartialDB &
  sourceVotes.PartialDB

export type { Actor, ActorEntry } from './actor'
export type { Account, AccountEntry } from './account'
export type { AccountDevice } from './account-device'
export type { Device } from './device'
export type { AuthorizationRequest } from './authorization-request'
export type { Token } from './token'
export type { UsedRefreshToken } from './used-refresh-token'
export type { RepoRoot } from './repo-root'
export type { RefreshToken } from './refresh-token'
export type { AppPassword } from './app-password'
export type { InviteCode, InviteCodeUse } from './invite-code'
export type { EmailToken, EmailTokenPurpose } from './email-token'
export type { Sources, SourcesEntry } from './sources'
export type { SourceVotes, SourceVotesEntry } from './source-votes'
