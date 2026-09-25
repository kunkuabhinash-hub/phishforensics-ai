import type {
  CanonicalThreatIntelligence,
  CrossInvestigationPatternComparison,
  CrossInvestigationPatternExplanation,
  BehavioralPatternMatch,
  PatternEvidenceSupport,
  ExplanationEvidenceReference,
  PatternNextInvestigationAction
} from '../../../../shared/types/threat-intelligence.ts';

export function explainCrossInvestigationComparison(
  comparison: CrossInvestigationPatternComparison,
  investigations: CanonicalThreatIntelligence[]
): CrossInvestigationPatternExplanation[] {
  const explanations: CrossInvestigationPatternExplanation[] = [];

  const allPatterns = [
    ...comparison.sharedPatterns,
    ...comparison.contradictoryPatterns,
    ...comparison.unknownPatterns,
    ...Object.values(comparison.uniquePatternsByInvestigation).flat()
  ];

  const investigationMap: Record<string, CanonicalThreatIntelligence> = {};
  for (const inv of investigations) {
    investigationMap[inv.investigation.id] = inv;
  }

  for (const pattern of allPatterns) {
    const evidenceSupportByInvestigation: Record<string, PatternEvidenceSupport> = {};
    const unresolvedUncertainty: string[] = [];
    const suggestedNextActions: PatternNextInvestigationAction[] = [];
    let isTemporalUncertain = false;
    let hasConflictingEvidenceInPattern = false;

    // Resolve evidence for each participating investigation
    for (const invId of pattern.investigationIds) {
      const inv = investigationMap[invId];
      if (!inv) {
        unresolvedUncertainty.push(`Investigation ${invId} not found in provided canonical records.`);
        continue;
      }

      const status = pattern.statusByInvestigation[invId];
      const evidenceIds = pattern.supportingEvidenceByInvestigation[invId] || [];

      const supportingEvidence: ExplanationEvidenceReference[] = [];
      const conflictingEvidence: ExplanationEvidenceReference[] = []; // In a real deeper pass, we might cross-reference conflicting findings. For now, empty unless explicitly known.
      const missingEvidenceIds: string[] = [];
      const artifactIdsSet = new Set<string>();

      for (const evId of evidenceIds) {
        const ev = inv.evidence.find(e => e.id === evId);
        if (ev) {
          if (ev.artifactId) artifactIdsSet.add(ev.artifactId);
          supportingEvidence.push({
            evidenceId: ev.id,
            artifactId: ev.artifactId || 'unknown',
            evidenceType: ev.type,
            status: ev.status,
            safeRepresentation: ev.sanitizedContent || ev.rawContent,
            originalDescription: ev.description,
            timestamp: ev.timestamp
          });
          if (ev.timestamp) {
            isTemporalUncertain = true; // Any timestamp across investigations means we should note temporal uncertainty.
          }
        } else {
          missingEvidenceIds.push(evId);
        }
      }

      if (missingEvidenceIds.length > 0) {
        unresolvedUncertainty.push(`Investigation ${invId} is missing evidence references: ${missingEvidenceIds.join(', ')}`);
        suggestedNextActions.push({
          action: 'Review missing artifacts',
          reason: `Evidence IDs ${missingEvidenceIds.join(', ')} referenced by pattern ${pattern.label} are missing from CanonicalThreatIntelligence.`,
          investigationId: invId
        });
      }

      // Check if the original investigation has unresolved questions or warnings that we can pull in
      if (inv.investigationQuality.unresolvedQuestions.length > 0) {
        suggestedNextActions.push({
          action: 'Review existing investigation unresolved questions',
          reason: inv.investigationQuality.unresolvedQuestions[0],
          investigationId: invId
        });
      }

      evidenceSupportByInvestigation[invId] = {
        investigationId: invId,
        status,
        supportingEvidence,
        conflictingEvidence,
        missingEvidenceIds,
        affectedArtifactIds: Array.from(artifactIdsSet)
      };
    }

    // Determine defensive interpretation
    let defensiveInterpretation = 'Current evidence is insufficient to establish the pattern';
    if (pattern.status === 'shared') {
      defensiveInterpretation = 'Repeated behavioral mechanism is observable across investigations.';
    } else if (pattern.status === 'unique') {
      defensiveInterpretation = 'Behavior is uniquely supported in a single investigation.';
    } else if (pattern.status === 'conflicted') {
      defensiveInterpretation = 'Investigations contain conflicting observations or mixed confidence levels.';
      hasConflictingEvidenceInPattern = true;
    } else if (pattern.status === 'unknown') {
      defensiveInterpretation = 'Evidence is incomplete or unknown across investigations.';
    }

    if (isTemporalUncertain) {
      unresolvedUncertainty.push('Evidence occurs at observed times, but temporal ordering is incomplete and no causal relationship is established.');
    }

    if (hasConflictingEvidenceInPattern) {
      suggestedNextActions.push({
        action: 'Investigate contradictory evidence',
        reason: 'The pattern exhibits conflicting states across investigations.'
      });
    }

    explanations.push({
      patternId: pattern.patternId,
      patternType: pattern.patternType,
      patternDescription: `Behavioral pattern: ${pattern.label}`,
      comparisonStatus: pattern.status,
      participatingInvestigationIds: pattern.investigationIds,
      evidenceSupportByInvestigation,
      defensiveInterpretation,
      unresolvedUncertainty,
      suggestedNextActions
    });
  }

  return explanations;
}
