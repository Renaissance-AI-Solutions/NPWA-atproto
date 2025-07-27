import { Kysely, sql } from 'kysely'

export async function up(db: Kysely<unknown>): Promise<void> {
  // Create the reporter_stats materialized view
  await db.schema
    .createView('reporter_stats')
    .materialized()
    .ifNotExists()
    .as(
      sql`
        SELECT 
          reporters.reporter_did as did,
          COALESCE(account_report_count, 0) as "accountReportCount",
          COALESCE(record_report_count, 0) as "recordReportCount",
          COALESCE(reported_account_count, 0) as "reportedAccountCount",
          COALESCE(reported_record_count, 0) as "reportedRecordCount",
          COALESCE(takendown_account_count, 0) as "takendownAccountCount",
          COALESCE(takendown_record_count, 0) as "takendownRecordCount",
          COALESCE(labeled_account_count, 0) as "labeledAccountCount",
          COALESCE(labeled_record_count, 0) as "labeledRecordCount"
        FROM (
          SELECT DISTINCT "createdBy" as reporter_did
          FROM moderation_event
          WHERE "action" = 'tools.ozone.moderation.defs#modEventReport'
        ) reporters
        LEFT JOIN (
          SELECT 
            "createdBy" as reporter_did,
            COUNT(*) as account_report_count,
            COUNT(DISTINCT "subjectDid") as reported_account_count
          FROM moderation_event
          WHERE "action" = 'tools.ozone.moderation.defs#modEventReport'
            AND "subjectUri" IS NULL
          GROUP BY "createdBy"
        ) account_reports ON reporters.reporter_did = account_reports.reporter_did
        LEFT JOIN (
          SELECT 
            "createdBy" as reporter_did,
            COUNT(*) as record_report_count,
            COUNT(DISTINCT "subjectUri") as reported_record_count
          FROM moderation_event
          WHERE "action" = 'tools.ozone.moderation.defs#modEventReport'
            AND "subjectUri" IS NOT NULL
          GROUP BY "createdBy"
        ) record_reports ON reporters.reporter_did = record_reports.reporter_did
        LEFT JOIN (
          SELECT 
            reports."createdBy" as reporter_did,
            COUNT(DISTINCT actions."subjectDid") as takendown_account_count
          FROM moderation_event reports
          JOIN moderation_event actions ON reports."subjectDid" = actions."subjectDid"
          WHERE reports."action" = 'tools.ozone.moderation.defs#modEventReport'
            AND reports."subjectUri" IS NULL
            AND actions."action" = 'tools.ozone.moderation.defs#modEventTakedown'
            AND actions."subjectUri" IS NULL
            AND actions."createdAt" >= reports."createdAt"
          GROUP BY reports."createdBy"
        ) account_takedowns ON reporters.reporter_did = account_takedowns.reporter_did
        LEFT JOIN (
          SELECT 
            reports."createdBy" as reporter_did,
            COUNT(DISTINCT actions."subjectUri") as takendown_record_count
          FROM moderation_event reports
          JOIN moderation_event actions ON reports."subjectUri" = actions."subjectUri"
          WHERE reports."action" = 'tools.ozone.moderation.defs#modEventReport'
            AND reports."subjectUri" IS NOT NULL
            AND actions."action" = 'tools.ozone.moderation.defs#modEventTakedown'
            AND actions."subjectUri" IS NOT NULL
            AND actions."createdAt" >= reports."createdAt"
          GROUP BY reports."createdBy"
        ) record_takedowns ON reporters.reporter_did = record_takedowns.reporter_did
        LEFT JOIN (
          SELECT 
            reports."createdBy" as reporter_did,
            COUNT(DISTINCT actions."subjectDid") as labeled_account_count
          FROM moderation_event reports
          JOIN moderation_event actions ON reports."subjectDid" = actions."subjectDid"
          WHERE reports."action" = 'tools.ozone.moderation.defs#modEventReport'
            AND reports."subjectUri" IS NULL
            AND actions."action" = 'tools.ozone.moderation.defs#modEventLabel'
            AND actions."subjectUri" IS NULL
            AND actions."createdAt" >= reports."createdAt"
          GROUP BY reports."createdBy"
        ) account_labels ON reporters.reporter_did = account_labels.reporter_did
        LEFT JOIN (
          SELECT 
            reports."createdBy" as reporter_did,
            COUNT(DISTINCT actions."subjectUri") as labeled_record_count
          FROM moderation_event reports
          JOIN moderation_event actions ON reports."subjectUri" = actions."subjectUri"
          WHERE reports."action" = 'tools.ozone.moderation.defs#modEventReport'
            AND reports."subjectUri" IS NOT NULL
            AND actions."action" = 'tools.ozone.moderation.defs#modEventLabel'
            AND actions."subjectUri" IS NOT NULL
            AND actions."createdAt" >= reports."createdAt"
          GROUP BY reports."createdBy"
        ) record_labels ON reporters.reporter_did = record_labels.reporter_did
      `
    )
    .execute()

  // Create unique index on the did column
  await db.schema
    .createIndex('reporter_stats_did_idx')
    .unique()
    .on('reporter_stats')
    .column('did')
    .execute()
}

export async function down(db: Kysely<unknown>): Promise<void> {
  await db.schema.dropView('reporter_stats').materialized().execute()
}