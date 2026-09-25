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

  // Ensure default fallback values for critical structural fields
  const safeResult: ProviderAnalysisResult = {
    suggestedVerdict: rawReasoning.suggestedVerdict || 'unknown',
    suggestedSeverity: rawReasoning.suggestedSeverity || 'unknown',
    suggestedRiskScore: validateConfidence(rawReasoning.suggestedRiskScore, -1) === -1 ? null : validateConfidence(rawReasoning.suggestedRiskScore),
    confidenceScore: validateConfidence(rawReasoning.confidenceScore, 0),
    summary: rawReasoning.summary || 'Analysis completed with insufficient reasoning details.',
    verdictJustification: rawReasoning.verdictJustification || 'No justification provided by reasoning engine.',
    
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
      primaryObjective: rawReasoning.attackerIntent?.primaryObjective || 'Unknown',
      secondaryObjectives: ensureArray<string>(rawReasoning.attackerIntent?.secondaryObjectives),
      targetedAsset: rawReasoning.attackerIntent?.targetedAsset || 'Unknown',
      intendedVictimAction: rawReasoning.attackerIntent?.intendedVictimAction || 'Unknown',
      potentialImpact: rawReasoning.attackerIntent?.potentialImpact || 'Unknown',
      supportingEvidenceIds: validateEvidenceIds(rawReasoning.attackerIntent?.supportingEvidenceIds, 'attacker intent'),
      confidence: validateConfidence(rawReasoning.attackerIntent?.confidence, 0),
      uncertaintyNotes: rawReasoning.attackerIntent?.uncertaintyNotes || null,
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
    
    attackDNAAttributes: ensureArray<any>(rawReasoning.attackDNAAttributes).map(dna => ({
      category: dna.category || 'General',
      characteristic: dna.characteristic || 'Unknown',
      value: dna.value || '',
      supportingEvidenceIds: validateEvidenceIds(dna.supportingEvidenceIds, `Attack DNA attribute "${dna.characteristic}"`),
      status: dna.status || 'unknown',
      confidence: validateConfidence(dna.confidence, 0),
      explanation: dna.explanation || '',
    })),
    
    reconstructionStages: ensureArray<any>(rawReasoning.reconstructionStages).map(stage => ({
      stageName: stage.stageName || 'Unknown Stage',
      description: stage.description || '',
      supportingEvidenceIds: validateEvidenceIds(stage.supportingEvidenceIds, `reconstruction stage "${stage.stageName}"`),
      confidence: validateConfidence(stage.confidence, 0),
      status: stage.status || 'unknown',
      victimAction: stage.victimAction,
      safeConsequence: stage.safeConsequence,
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
