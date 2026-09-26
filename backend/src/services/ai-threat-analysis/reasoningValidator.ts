import type { EvidenceItem, NormalizedArtifact } from '../../../../shared/types/threat-intelligence.ts';
import type { AIReasoningResult } from './reasoningSchema.ts';
import type { ProviderAnalysisResult, ValidationAuditReport } from './types.ts';

/**
 * ============================================================================
 * PHISHFORENSICS AI — REASONING VALIDATION BOUNDARY
 * ============================================================================
 *
 * Validates raw AI provider output to ensure evidence traceability,
 * prevent hallucinations, and guarantee structural conformity before
 * canonical assembly.
 */

export class ReasoningValidationError extends Error {
  constructor(message: string) {
    super(`Reasoning Validation Failed: ${message}`);
    this.name = 'ReasoningValidationError';
  }
}

/**
 * Validates the raw reasoning result from the AI and maps it safely to the
 * ProviderAnalysisResult expected by the pipeline assembler.
 */
export function validateAndMapReasoning(
  rawReasoning: Partial<AIReasoningResult>,
  validEvidence: EvidenceItem[],
  validArtifacts: NormalizedArtifact[] = []
): { mappedResult: ProviderAnalysisResult; validationAudit: ValidationAuditReport } {
  const validEvidenceIds = new Set(validEvidence.map(e => e.id));
  const validArtifactIds = new Set(validArtifacts.map(a => a.id));
  
  const warnings: string[] = [];
  const invalidEvidenceReferences: string[] = [];
  const invalidArtifactReferences: string[] = [];

  // Helper to validate and filter evidence IDs to prevent hallucinations
  const validateEvidenceIds = (ids: string[] | undefined, context: string): string[] => {
    if (!ids || !Array.isArray(ids)) return [];
    
    const validIds: string[] = [];
    for (const id of ids) {
      if (validEvidenceIds.has(id)) {
        validIds.push(id);
      } else {
        const warning = `AI attempted to reference unknown evidence ID "${id}" in ${context}.`;
        console.warn(`[Hallucination Guard] ${warning}`);
        warnings.push(warning);
        invalidEvidenceReferences.push(id);
      }
    }
    return validIds;
  };

  // Helper to validate artifact references (if AI somehow references them directly in reasoning fields)
  // Although the schema currently only links Evidence -> Artifact, this future-proofs it.
  const validateArtifactId = (id: string | undefined, context: string): string | undefined => {
    if (!id) return undefined;
    if (validArtifactIds.size > 0 && !validArtifactIds.has(id)) {
      const warning = `AI attempted to reference unknown artifact ID "${id}" in ${context}.`;
      console.warn(`[Hallucination Guard] ${warning}`);
      warnings.push(warning);
      invalidArtifactReferences.push(id);
      return undefined;
    }
    return id;
  };

  // Helper to safely parse and bound confidence values between 0 and 100
  const validateConfidence = (val: any, fallback: number = 0): number => {
    if (typeof val === 'number' && Number.isFinite(val)) {
      return Math.max(0, Math.min(100, val));
    }
    return fallback;
  };

  // Helper to ensure values expected to be arrays are defensively normalized
  const ensureArray = <T>(val: any): T[] => Array.isArray(val) ? val : (val && typeof val === 'object' ? [val] : []);

  // Safe alias extraction for nested summary object if provided by AI
  const summaryObj = (typeof rawReasoning.summary === 'object' && rawReasoning.summary !== null && !Array.isArray(rawReasoning.summary))
    ? (rawReasoning.summary as Record<string, any>)
    : null;

  // 1. suggestedVerdict: flat first, then summary.verdict, fallback 'unknown'
  const rawVerdict = ((typeof rawReasoning.suggestedVerdict === 'string' && rawReasoning.suggestedVerdict.trim())
    ? rawReasoning.suggestedVerdict
    : (summaryObj && typeof summaryObj.verdict === 'string' && summaryObj.verdict.trim()
      ? summaryObj.verdict
      : 'unknown')).toLowerCase();

  let resolvedVerdict: 'phishing' | 'suspicious' | 'safe' | 'unknown' = 'unknown';
  if (rawVerdict === 'phishing' || rawVerdict === 'malicious') resolvedVerdict = 'phishing';
  else if (rawVerdict === 'suspicious') resolvedVerdict = 'suspicious';
  else if (rawVerdict === 'safe' || rawVerdict === 'benign') resolvedVerdict = 'safe';
  else resolvedVerdict = 'unknown';

  // 2. suggestedSeverity: flat first, then summary.severity, fallback 'unknown'
  const rawSeverity = ((typeof rawReasoning.suggestedSeverity === 'string' && rawReasoning.suggestedSeverity.trim())
    ? rawReasoning.suggestedSeverity
    : (summaryObj && typeof summaryObj.severity === 'string' && summaryObj.severity.trim()
      ? summaryObj.severity
      : 'unknown')).toLowerCase();

  let resolvedSeverity: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown' = 'unknown';
  if (['critical', 'high', 'medium', 'low', 'info'].includes(rawSeverity)) {
    resolvedSeverity = rawSeverity as any;
  } else {
    resolvedSeverity = 'unknown';
  }

  // 3. suggestedRiskScore: flat first, then summary.riskScore
  const rawRiskVal = typeof rawReasoning.suggestedRiskScore === 'number'
    ? rawReasoning.suggestedRiskScore
    : (summaryObj && typeof summaryObj.riskScore === 'number' ? summaryObj.riskScore : undefined);
  const resolvedRiskScore = validateConfidence(rawRiskVal, -1) === -1 ? null : validateConfidence(rawRiskVal);

  // 4. confidenceScore: flat first, then summary.confidenceScore
  const rawConfidenceVal = typeof rawReasoning.confidenceScore === 'number'
    ? rawReasoning.confidenceScore
    : (summaryObj && typeof summaryObj.confidenceScore === 'number' ? summaryObj.confidenceScore : undefined);
  const resolvedConfidence = validateConfidence(rawConfidenceVal, 0);

  // 5. summary: flat string first, then summary.executiveSummary, fallback default
  const resolvedSummary = (typeof rawReasoning.summary === 'string' && rawReasoning.summary.trim())
    ? rawReasoning.summary
    : (summaryObj && typeof summaryObj.executiveSummary === 'string' && summaryObj.executiveSummary.trim()
      ? summaryObj.executiveSummary
      : 'Analysis completed with insufficient reasoning details.');

  // 6. verdictJustification: flat first, then summary.executiveSummary, fallback default
  const resolvedJustification = (typeof rawReasoning.verdictJustification === 'string' && rawReasoning.verdictJustification.trim())
    ? rawReasoning.verdictJustification
    : (summaryObj && typeof summaryObj.executiveSummary === 'string' && summaryObj.executiveSummary.trim()
      ? summaryObj.executiveSummary
      : 'No justification provided by reasoning engine.');

  // Attacker Intent alias resolution
  const intentObj = (typeof rawReasoning.attackerIntent === 'object' && rawReasoning.attackerIntent !== null && !Array.isArray(rawReasoning.attackerIntent))
    ? (rawReasoning.attackerIntent as Record<string, any>)
    : null;

  const resolvedPrimaryObjective = (intentObj && typeof intentObj.primaryObjective === 'string' && intentObj.primaryObjective.trim())
    ? intentObj.primaryObjective
    : (intentObj && typeof intentObj.primaryGoal === 'string' && intentObj.primaryGoal.trim()
      ? intentObj.primaryGoal
      : 'Unknown');

  const resolvedIntendedVictimAction = (intentObj && typeof intentObj.intendedVictimAction === 'string' && intentObj.intendedVictimAction.trim())
    ? intentObj.intendedVictimAction
    : 'Unknown';

  const resolvedPotentialImpact = (intentObj && typeof intentObj.potentialImpact === 'string' && intentObj.potentialImpact.trim())
    ? intentObj.potentialImpact
    : 'Unknown';

  // Ensure default fallback values for critical structural fields
  const safeResult: ProviderAnalysisResult = {
    suggestedVerdict: resolvedVerdict as any,
    suggestedSeverity: resolvedSeverity as any,
    suggestedRiskScore: resolvedRiskScore,
    confidenceScore: resolvedConfidence,
    summary: resolvedSummary,
    verdictJustification: resolvedJustification,
    
    findings: ensureArray<any>(rawReasoning.findings).map(f => ({
      category: f.category || 'general_observation',
      title: f.title || 'Uncategorized Finding',
      description: f.description || '',
      supportingEvidenceIds: validateEvidenceIds(f.supportingEvidenceIds, `finding "${f.title}"`),
      contradictingEvidenceIds: validateEvidenceIds(f.contradictingEvidenceIds, `finding contradiction "${f.title}"`),
      confidence: validateConfidence(f.confidence, 0),
      status: f.status || 'unverified',
      severity: f.severity || 'info',
      impact: f.impact || 'Unknown',
    })),
    
    attackerIntent: {
      primaryObjective: resolvedPrimaryObjective,
      secondaryObjectives: ensureArray<string>(intentObj?.secondaryObjectives || (intentObj as any)?.secondaryGoals),
      targetedAsset: (intentObj && typeof intentObj.targetedAsset === 'string' && intentObj.targetedAsset.trim()) ? intentObj.targetedAsset : 'Unknown',
      intendedVictimAction: resolvedIntendedVictimAction,
      potentialImpact: resolvedPotentialImpact,
      supportingEvidenceIds: validateEvidenceIds(intentObj?.supportingEvidenceIds, 'attacker intent'),
      confidence: validateConfidence(intentObj?.confidence, 0),
      uncertaintyNotes: intentObj?.uncertaintyNotes || null,
    },
    
    victimRequestedAction: {
      actionType: rawReasoning.victimRequestedAction?.actionType || 'unknown',
      description: rawReasoning.victimRequestedAction?.description || 'No explicit requested victim action established.',
      urgencyLevel: rawReasoning.victimRequestedAction?.urgencyLevel || 'unknown',
      targetChannel: rawReasoning.victimRequestedAction?.targetChannel || 'unknown',
      supportingEvidenceIds: validateEvidenceIds(rawReasoning.victimRequestedAction?.supportingEvidenceIds, 'victim requested action'),
      confidence: validateConfidence(rawReasoning.victimRequestedAction?.confidence, 0),
    },
    
    socialEngineering: ensureArray<any>(rawReasoning.socialEngineering).map(se => ({
      techniqueName: se.techniqueName || 'Unknown Technique',
      explanation: se.explanation || '',
      supportingEvidenceIds: validateEvidenceIds(se.supportingEvidenceIds, `social engineering technique "${se.techniqueName}"`),
      confidence: validateConfidence(se.confidence, 0),
      status: se.status || 'inferred',
    })),
    
    attackDNAAttributes: ensureArray<any>(
      rawReasoning.attackDNAAttributes || (rawReasoning as any).attackDna?.behavioralFingerprints
    ).map(dna => ({
      category: dna.category || 'General',
      characteristic: dna.characteristic || dna.indicator || 'Unknown',
      value: dna.value || dna.indicator || '',
      supportingEvidenceIds: validateEvidenceIds(dna.supportingEvidenceIds, `Attack DNA attribute "${dna.characteristic || dna.indicator || 'Unknown'}"`),
      status: dna.status || 'unknown',
      confidence: validateConfidence(dna.confidence, 0),
      explanation: dna.explanation || '',
    })),
    
    reconstructionStages: ensureArray<any>(
      rawReasoning.reconstructionStages || (rawReasoning as any).defensiveReconstruction?.stages
    ).map(stage => ({
      stageName: stage.stageName || 'Unknown Stage',
      description: stage.description || '',
      supportingEvidenceIds: validateEvidenceIds(stage.supportingEvidenceIds, `reconstruction stage "${stage.stageName}"`),
      confidence: validateConfidence(stage.confidence, 0),
      status: stage.status || 'unknown',
      victimAction: stage.victimAction || stage.requestedAction,
      safeConsequence: stage.safeConsequence || stage.hypotheticalConsequence,
      uncertaintyNotes: stage.uncertaintyNotes,
    })),
    
    crossArtifactCorrelations: ensureArray<any>(rawReasoning.crossArtifactCorrelations).map((corr, idx) => {
      const validArtifactIds = (corr.artifactIds || []).filter(aId => {
        const isValid = validArtifacts.some(a => a.id === aId);
        if (!isValid) {
          warnings.push(`[Hallucination Guard] AI referenced unknown artifact ID "${aId}" in correlation.`);
          if (!invalidArtifactReferences.includes(aId)) invalidArtifactReferences.push(aId);
        }
        return isValid;
      });
      return {
        artifactIds: validArtifactIds,
        supportingEvidenceIds: validateEvidenceIds(corr.supportingEvidenceIds, 'cross-artifact correlation'),
        relationshipType: corr.relationshipType || 'unknown_relationship',
        explanation: corr.explanation || 'No explanation provided',
        status: corr.status || 'unknown',
      };
    }),
    
    unverifiedClaims: ensureArray<any>(rawReasoning.unverifiedClaims).map(claim => ({
      claim: claim.claim || '',
      reasonUnverified: claim.reasonUnverified || '',
      evidenceIds: validateEvidenceIds(claim.evidenceIds, 'unverified claim'),
    })),
    
    conflictingSignals: ensureArray<any>(rawReasoning.conflictingSignals).map(conflict => ({
      signalA: conflict.signalA || '',
      signalB: conflict.signalB || '',
      explanation: conflict.explanation || '',
    })),
    
    missingEvidence: ensureArray<any>(rawReasoning.missingEvidence).map(missing => ({
      missingItem: missing.missingItem || 'Unknown Data',
      whyNeeded: missing.whyNeeded || '',
      impactOnAnalysis: missing.impactOnAnalysis || '',
    })),
    
    unresolvedQuestions: ensureArray<string>(rawReasoning.unresolvedQuestions),
    nextInvestigationActions: ensureArray<any>(rawReasoning.nextInvestigationActions).map(action => ({
      action: action.action || 'Unknown action',
      reason: action.reason || 'No reason provided',
    })),
    
    defensiveRecommendations: ensureArray<any>(rawReasoning.defensiveRecommendations).map(rec => ({
      priority: rec.priority || 'medium',
      title: rec.title || 'General Recommendation',
      action: rec.action || '',
      rationale: rec.rationale || '',
      supportingEvidenceIds: validateEvidenceIds(rec.supportingEvidenceIds, `defensive recommendation "${rec.title}"`),
      safeNextStep: rec.safeNextStep || '',
      supportingFindingIds: [], // Resolved at canonical assembly stage
    })),
    
    educationalExplanation: {
      whatHappened: rawReasoning.educationalExplanation?.whatHappened || 'A suspicious artifact was analyzed.',
      knownFacts: rawReasoning.educationalExplanation?.knownFacts || [],
      inferredAssumptions: rawReasoning.educationalExplanation?.inferredAssumptions || [],
      unknownFactors: rawReasoning.educationalExplanation?.unknownFactors || [],
      whyThisWorks: rawReasoning.educationalExplanation?.whyThisWorks || 'Attackers use various psychological tricks.',
      psychologicalMechanism: rawReasoning.educationalExplanation?.psychologicalMechanism || 'Unknown',
      saferAlternativeBehavior: rawReasoning.educationalExplanation?.saferAlternativeBehavior || 'Verify before acting.',
      keySignalsNoticed: [], // Handled by canonical assembler
    },
    
    attackNarrative: {
      initialSignal: rawReasoning.attackNarrative?.initialSignal || 'Initial interaction not clearly identified.',
      socialEngineeringMechanism: rawReasoning.attackNarrative?.socialEngineeringMechanism || 'Not applicable or unknown.',
      requestedVictimAction: rawReasoning.attackNarrative?.requestedVictimAction || 'No requested action identified.',
      technicalCharacteristics: rawReasoning.attackNarrative?.technicalCharacteristics || 'None identified.',
      defensiveReconstruction: rawReasoning.attackNarrative?.defensiveReconstruction || 'Could not reconstruct attack path.',
      unknownFactors: rawReasoning.attackNarrative?.unknownFactors || [],
    },
    
    limitations: rawReasoning.limitations || [],
    assumptions: rawReasoning.assumptions || [],
  };

  const validationAudit: ValidationAuditReport = {
    validationStatus: warnings.length > 0 ? 'warnings_generated' : 'success',
    warnings,
    invalidEvidenceReferences,
    invalidArtifactReferences,
  };

  return { mappedResult: safeResult, validationAudit };
}
