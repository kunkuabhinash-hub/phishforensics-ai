import type {
  CanonicalThreatIntelligence,
  AnalystInvestigationView,
  CrossInvestigationPatternExplanation,
  AnalystIntelligenceBrief,
  AnalystBriefNextAction
} from '../../../../shared/types/threat-intelligence.ts';

export function buildAnalystIntelligenceBrief(
  canonical: CanonicalThreatIntelligence,
  analystView: AnalystInvestigationView,
  crossInvestigationExplanations: CrossInvestigationPatternExplanation[] = []
): AnalystIntelligenceBrief {
  
  const recommendedNextActions: AnalystBriefNextAction[] = [];

  // Derive recommended next actions from various sources
  for (const m of canonical.missingEvidence) {
    recommendedNextActions.push({
      action: 'Retrieve missing evidence',
      reason: m.reason,
      source: 'missing_evidence'
    });
  }

  for (const q of canonical.investigationQuality.unresolvedQuestions) {
    recommendedNextActions.push({
      action: 'Investigate unresolved question',
      reason: q,
      source: 'unresolved_question'
    });
  }

  for (const w of canonical.investigationQuality.analystWarnings) {
    recommendedNextActions.push({
      action: 'Review quality warning',
      reason: w,
      source: 'quality_warning'
    });
  }

  for (const exp of crossInvestigationExplanations) {
    // Only pull actions for this specific investigation, or global ones
    const relevantActions = exp.suggestedNextActions.filter(a => !a.investigationId || a.investigationId === canonical.investigation.id);
    for (const a of relevantActions) {
      // Avoid exact duplicates
      if (!recommendedNextActions.some(r => r.reason === a.reason && r.action === a.action)) {
        recommendedNextActions.push({
          action: a.action,
          reason: a.reason,
          source: 'cross_investigation'
        });
      }
    }
  }

  // Construct deterministic executive summary
  const executiveSummary: string[] = [];
  
  if (canonical.findings.length > 0) {
    const supported = analystView.findingExplanations.filter(e => e.explanationState === 'supported').length;
    if (supported > 0) {
      executiveSummary.push(`Investigation established ${supported} fully supported suspicious findings based on extracted evidence.`);
    }
    const conflicted = analystView.findingExplanations.filter(e => e.explanationState === 'conflicted').length;
    if (conflicted > 0) {
      executiveSummary.push(`Findings contain conflicting evidence requiring manual analyst review (${conflicted} conflicted findings).`);
    }
    const insufficient = analystView.findingExplanations.filter(e => e.explanationState === 'insufficient_evidence').length;
    if (insufficient > 0) {
      executiveSummary.push(`Evidence is insufficient to establish conclusion for ${insufficient} findings.`);
    }
  } else {
    executiveSummary.push('No findings were identified from the available artifacts.');
  }

  if (canonical.crossArtifactCorrelations.length > 0) {
    executiveSummary.push(`Multiple artifacts share an observable pattern (${canonical.crossArtifactCorrelations.length} correlations identified).`);
  }

  if (canonical.missingEvidence.length > 0 || canonical.investigationQuality.unresolvedQuestions.length > 0) {
    executiveSummary.push('Important telemetry or evidence is missing, limiting analytical certainty.');
  }

  if (crossInvestigationExplanations.some(e => e.participatingInvestigationIds.includes(canonical.investigation.id))) {
    executiveSummary.push('This investigation shares observable behavioral characteristics with other historical investigations.');
  }

  if (executiveSummary.length === 0) {
    executiveSummary.push('Investigation completed with no notable anomalies or evidence correlations.');
  }

  return {
    investigationIdentity: {
      investigationId: canonical.investigation.id,
      timestamp: canonical.investigation.timestamp,
      status: canonical.investigation.status,
    },
    executiveSummary,
    threatAssessmentSummary: {
      verdict: canonical.threatAssessment.verdict,
      severity: canonical.threatAssessment.severity,
    },
    keyFindings: analystView.findingExplanations,
    evidenceHighlights: canonical.evidence.filter(e => 
      canonical.findings.some(f => f.supportingEvidenceIds.includes(e.id)) ||
      canonical.crossArtifactCorrelations.some(c => c.supportingEvidenceIds?.includes(e.id))
    ),
    attackerBehaviorSummary: analystView.attackDNA,
    victimActionSummary: canonical.victimRequestedAction,
    reconstructionSummary: analystView.reconstruction,
    uncertaintySummary: canonical.uncertaintyReport,
    missingEvidenceSummary: canonical.missingEvidence,
    investigationQualitySummary: canonical.investigationQuality,
    crossArtifactSummary: analystView.crossArtifactCorrelations,
    crossInvestigationSummary: crossInvestigationExplanations,
    recommendedNextActions,
    traceabilitySummary: analystView.traceabilityAudit,
  };
}
