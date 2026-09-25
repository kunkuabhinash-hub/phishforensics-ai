import type { 
  CanonicalThreatIntelligence, 
  AnalystInvestigationView,
  AnalystInvestigationSummary,
  AnalystFindingView,
  AnalystAttackDNAView,
  AnalystReconstructionStageView,
  AnalystCorrelationView,
  AnalystTimelineEventView
} from '../../../../../shared/types/threat-intelligence.ts';
import { buildFindingExplanation } from './findingExplanation.ts';
import { buildInvestigationTraceabilityAudit } from './traceabilityAudit.ts';

/**
 * Projects a CanonicalThreatIntelligence result into a frontend-friendly 
 * AnalystInvestigationView model. 
 * 
 * This is a pure mapping function. It does not recalculate verdicts, risk scores,
 * or relationships. It preserves all evidence IDs and limits the presentation
 * to what is supported by the canonical schema.
 */
export function buildAnalystInvestigationView(canonical: CanonicalThreatIntelligence): AnalystInvestigationView {
  
  // 1. Investigation Summary
  const summary: AnalystInvestigationSummary = {
    investigationId: canonical.investigation.id,
    verdict: canonical.threatAssessment.verdict,
    severity: canonical.threatAssessment.severity,
    riskScore: canonical.threatAssessment.riskScore,
    completenessStatus: canonical.investigationQuality.completenessStatus,
    artifactCount: canonical.artifacts.length,
    evidenceCount: canonical.evidence.length,
    findingCount: canonical.findings.length,
    unresolvedQuestionCount: canonical.investigationQuality.unresolvedQuestions.length,
    missingEvidenceCount: canonical.missingEvidence.length,
    correlationCount: canonical.crossArtifactCorrelations.length,
  };

  // 2. Key Findings
  const keyFindings: AnalystFindingView[] = canonical.findings.map(finding => ({
    findingId: finding.id,
    title: finding.title,
    description: finding.description,
    status: finding.status,
    severity: finding.severity,
    confidence: finding.confidence,
    supportingEvidenceIds: finding.supportingEvidenceIds,
    contradictingEvidenceIds: finding.contradictingEvidenceIds || [],
  }));

  // 3. Attack DNA
  const attackDNA: AnalystAttackDNAView[] = canonical.attackDNASource.attributes.map(dna => ({
    attributeId: dna.id,
    category: dna.category,
    characteristic: dna.characteristic,
    description: dna.explanation,
    status: dna.status,
    supportingEvidenceIds: dna.supportingEvidenceIds,
  }));

  // 4. Reconstruction Timeline
  const reconstruction: AnalystReconstructionStageView[] = canonical.reconstructionTimeline.map(stg => ({
    stageId: stg.stageId,
    stageName: stg.stageName,
    description: stg.description,
    status: stg.status,
    victimAction: stg.victimAction,
    safeConsequence: stg.safeConsequence,
    uncertaintyNotes: stg.uncertaintyNotes,
    supportingEvidenceIds: stg.supportingFindingIds.flatMap(fId => {
      // Trace back to original evidence for the presentation layer
      const finding = canonical.findings.find(f => f.id === fId);
      return finding ? finding.supportingEvidenceIds : [];
    }).filter((value, index, self) => self.indexOf(value) === index),
  }));

  // 5. Cross-Artifact Correlations
  const crossArtifactCorrelations: AnalystCorrelationView[] = canonical.crossArtifactCorrelations.map(corr => ({
    correlationId: corr.id,
    artifactIds: corr.artifactIds,
    relationshipType: corr.relationshipType,
    explanation: corr.explanation,
    status: corr.status,
    supportingEvidenceIds: corr.supportingEvidenceIds,
  }));

  // 6. Investigation Timeline
  const investigationTimeline: AnalystTimelineEventView[] = canonical.investigationTimeline.map(evt => ({
    eventId: evt.eventId,
    timestamp: evt.timestamp,
    timestampProvenance: evt.timestampProvenance,
    eventDescription: evt.eventDescription,
    status: evt.status,
    artifactIds: evt.artifactIds,
  }));
  
  // 7. Finding Explanations
  const findingExplanations = canonical.findings.map(f => buildFindingExplanation(f, canonical.evidence));

  return {
    summary,
    evidenceOverview: canonical.evidence,
    keyFindings,
    findingExplanations,
    uncertaintyAndUnknowns: canonical.uncertaintyReport,
    attackerIntent: canonical.attackerIntent,
    victimRequestedAction: canonical.victimRequestedAction,
    socialEngineering: canonical.socialEngineering,
    technicalIndicators: canonical.technicalIndicators,
    attackDNA,
    crossArtifactCorrelations,
    investigationTimeline,
    attackNarrative: canonical.attackNarrative,
    reconstruction,
    investigationQuality: canonical.investigationQuality,
    missingEvidence: canonical.missingEvidence,
    defensiveRecommendations: canonical.defensiveRecommendations,
    traceabilityAudit: buildInvestigationTraceabilityAudit(canonical),
  };
}

