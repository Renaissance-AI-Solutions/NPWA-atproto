import { Generated } from 'kysely'

export const aiAnalysisTableName = 'ai_analysis'

export interface AiAnalysis {
  id: Generated<number>
  sourceUri: string
  classifier: string
  label: string
  score: number
  analysisData: string | null
  createdAt: string
}

export type PartialDB = {
  [aiAnalysisTableName]: AiAnalysis
} 