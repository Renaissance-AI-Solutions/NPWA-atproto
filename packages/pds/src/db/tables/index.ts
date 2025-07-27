import * as users from './users'
import * as badgeClaims from './badge-claims'
import * as documents from './documents'
import * as accessLogs from './access-logs'
import * as aiAnalysis from './ai-analysis'
import * as livestreams from './livestreams'
import * as journalEntries from './journal-entries'
import * as moderation from './moderation'

// Export interfaces and table names
export type { Users } from './users'
export { usersTableName } from './users'
export type { BadgeClaims } from './badge-claims'
export { badgeClaimsTableName } from './badge-claims'
export type { Documents } from './documents'
export { documentsTableName } from './documents'
export type { AccessLogs } from './access-logs'
export { accessLogsTableName } from './access-logs'
export type { AiAnalysis } from './ai-analysis'
export { aiAnalysisTableName } from './ai-analysis'
export type { Livestreams } from './livestreams'
export { livestreamsTableName } from './livestreams'
export type { JournalEntries } from './journal-entries'
export { journalEntriesTableName } from './journal-entries'
export type { ModerationAction, ModerationActionSubjectBlob, ModerationReport, ModerationReportResolution } from './moderation'
export { actionTableName, actionSubjectBlobTableName, reportTableName, reportResolutionTableName } from './moderation'

// Combined database schema
export type DatabaseSchema = users.PartialDB &
  badgeClaims.PartialDB &
  documents.PartialDB &
  accessLogs.PartialDB &
  aiAnalysis.PartialDB &
  livestreams.PartialDB &
  journalEntries.PartialDB &
  moderation.PartialDB