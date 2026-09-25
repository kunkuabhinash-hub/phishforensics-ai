import type {
  FindingItem,
  EvidenceItem,
  FindingExplanation,
  ExplanationEvidenceReference,
  ExplanationState,
} from '../../../../shared/types/threat-intelligence.ts';

export function buildFindingExplanation(
  finding: FindingItem,
  evidenceItems: EvidenceItem[]
): FindingExplanation {
  
  const supportingEvidence: ExplanationEvidenceReference[] = [];
  const contradictingEvidence: ExplanationEvidenceReference[] = [];
  const missingEvidenceReferences: string[] = [];
  const artifactIdsSet = new Set<string>();

  const resolveEvidence = (evidenceId: string): ExplanationEvidenceReference | null => {
    const ev = evidenceItems.find(e => e.id === evidenceId);
    if (!ev) {
      return null;
    }
    
    if (ev.artifactId) {
      artifactIdsSet.add(ev.artifactId);
    }
    
    return {
      evidenceId: ev.id,
      artifactId: ev.artifactId || 'unknown',
      evidenceType: ev.type,
      status: ev.status,
      safeRepresentation: ev.sanitizedContent || ev.rawContent,
      originalDescription: ev.description,
      timestamp: ev.timestamp,
    };
  };

  // Resolve supporting evidence
  for (const evId of finding.supportingEvidenceIds) {
    const resolved = resolveEvidence(evId);
    if (resolved) {
      supportingEvidence.push(resolved);
    } else {
      missingEvidenceReferences.push(evId);
    }
  }

  // Resolve contradicting evidence
  for (const evId of (finding.contradictingEvidenceIds || [])) {
    const resolved = resolveEvidence(evId);
    if (resolved) {
      contradictingEvidence.push(resolved);
    } else {
      missingEvidenceReferences.push(evId);
    }
  }

  // Determine state
  let explanationState: ExplanationState = 'unknown';

  if (finding.status === 'unknown') {
    explanationState = 'unknown';
  } else if (supportingEvidence.length === 0) {
    explanationState = 'insufficient_evidence';
  } else if (contradictingEvidence.length > 0) {
    explanationState = 'conflicted';
  } else if (missingEvidenceReferences.length > 0 || finding.status === 'inferred' || finding.status === 'unverified') {
    explanationState = 'partially_supported';
  } else {
    explanationState = 'supported';
  }

  return {
    findingId: finding.id,
    conclusionSummary: finding.title, // Or a more detailed summary if available
    status: finding.status,
    explanationState,
    supportingEvidence,
    contradictingEvidence,
    missingEvidenceReferences,
    artifactIds: Array.from(artifactIdsSet),
  };
}
