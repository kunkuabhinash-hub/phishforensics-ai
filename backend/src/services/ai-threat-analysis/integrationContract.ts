import type {
  CanonicalThreatIntelligence,
  AnalystInvestigationView,
  AnalystIntelligenceBrief,
  CrossInvestigationPatternExplanation,
  CrossInvestigationPatternComparison
} from '../../../../shared/types/threat-intelligence.ts';
import type { RawArtifactInput, AnalysisInputOptions } from './types.ts';
import { ThreatAnalysisPipeline } from './threatAnalysisPipeline.ts';
import { buildAnalystInvestigationView } from './analystViewModel.ts';
import { buildAnalystIntelligenceBrief } from './analystIntelligenceBrief.ts';

export interface FullInvestigationResult {
  canonical: CanonicalThreatIntelligence;
  analystView: AnalystInvestigationView;
  intelligenceBrief: AnalystIntelligenceBrief;
}

/**
 * Main integration entry point for the backend.
 * Performs the AI threat analysis and executes all deterministic projections.
 */
export async function runFullInvestigation(
  rawInputs: RawArtifactInput | RawArtifactInput[],
  options: AnalysisInputOptions = {},
  crossInvestigationExplanations: CrossInvestigationPatternExplanation[] = [],
  customProvider?: any
): Promise<FullInvestigationResult> {
  const pipeline = new ThreatAnalysisPipeline(customProvider);
  
  // 1. Analyze and generate canonical truth
  const { canonicalResult } = await pipeline.analyzeWithAudit(rawInputs, options);
  
  // 2. Project Analyst Investigation View
  const analystView = buildAnalystInvestigationView(canonicalResult);
  
  // 3. Project Intelligence Brief
  const intelligenceBrief = buildAnalystIntelligenceBrief(canonicalResult, analystView, crossInvestigationExplanations);

  return {
    canonical: canonicalResult,
    analystView,
    intelligenceBrief
  };
}
