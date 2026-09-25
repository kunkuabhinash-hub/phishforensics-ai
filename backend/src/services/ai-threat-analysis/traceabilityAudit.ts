import type {
  CanonicalThreatIntelligence,
  InvestigationTraceabilityAudit,
  FindingTraceabilityRecord,
  EvidenceTraceabilityRecord,
  ArtifactTraceabilityRecord,
  TraceabilityState,
} from '../../../../shared/types/threat-intelligence.ts';

export function buildInvestigationTraceabilityAudit(
  intelligence: CanonicalThreatIntelligence
): InvestigationTraceabilityAudit {
  const unresolvedTraceabilityIssues: string[] = [];

  const evidenceAudits: Record<string, EvidenceTraceabilityRecord> = {};
  
  // Initialize evidence tracking
  for (const ev of intelligence.evidence) {
    evidenceAudits[ev.id] = {
      evidenceId: ev.id,
      artifactId: ev.artifactId || 'unknown',
      usedByFindingIds: [],
      usedAsSupportingEvidence: false,
      usedAsContradictingEvidence: false,
      usageState: 'unknown'
    };
  }

  const findingAudits: FindingTraceabilityRecord[] = [];
  let findingsWithSupportingEvidence = 0;
  let findingsWithContradictingEvidence = 0;
  let findingsWithMissingEvidence = 0;

  // Process findings
  for (const finding of intelligence.findings) {
    const missingEvidenceIds: string[] = [];
    let supportingResolved = 0;
    let contradictingResolved = 0;

    for (const evId of finding.supportingEvidenceIds) {
      if (evidenceAudits[evId]) {
        evidenceAudits[evId].usedAsSupportingEvidence = true;
        if (!evidenceAudits[evId].usedByFindingIds.includes(finding.id)) {
          evidenceAudits[evId].usedByFindingIds.push(finding.id);
        }
        supportingResolved++;
      } else {
        missingEvidenceIds.push(evId);
      }
    }

    const contradictingIds = finding.contradictingEvidenceIds || [];
    for (const evId of contradictingIds) {
      if (evidenceAudits[evId]) {
        evidenceAudits[evId].usedAsContradictingEvidence = true;
        if (!evidenceAudits[evId].usedByFindingIds.includes(finding.id)) {
          evidenceAudits[evId].usedByFindingIds.push(finding.id);
        }
        contradictingResolved++;
      } else {
        missingEvidenceIds.push(evId);
      }
    }

    let state: TraceabilityState = 'unknown';
    
    if (finding.status === 'unknown') {
      state = 'unknown';
    } else if (supportingResolved === 0) {
      state = 'untraceable';
    } else if (contradictingResolved > 0) {
      state = 'conflicted';
    } else if (missingEvidenceIds.length > 0) {
      state = 'partially_traceable';
    } else {
      state = 'fully_traceable';
    }

    if (supportingResolved > 0) findingsWithSupportingEvidence++;
    if (contradictingResolved > 0) findingsWithContradictingEvidence++;
    if (missingEvidenceIds.length > 0) findingsWithMissingEvidence++;

    if (state === 'untraceable') {
      unresolvedTraceabilityIssues.push(`Finding ${finding.id} has no resolvable supporting evidence.`);
    } else if (missingEvidenceIds.length > 0) {
      unresolvedTraceabilityIssues.push(`Finding ${finding.id} references missing evidence IDs: ${missingEvidenceIds.join(', ')}.`);
    }

    findingAudits.push({
      findingId: finding.id,
      status: finding.status,
      supportingEvidenceIds: finding.supportingEvidenceIds,
      contradictingEvidenceIds: contradictingIds,
      missingEvidenceIds,
      supportingEvidenceResolved: supportingResolved,
      contradictingEvidenceResolved: contradictingResolved,
      traceabilityState: state
    });
  }

  let evidenceUsedByFindings = 0;
  let unusedEvidenceItems = 0;

  // Finalize evidence states
  const evidenceAuditList = Object.values(evidenceAudits).map(ea => {
    if (ea.usedByFindingIds.length > 0) {
      ea.usageState = 'used';
      evidenceUsedByFindings++;
    } else {
      ea.usageState = 'unused';
      unusedEvidenceItems++;
    }
    return ea;
  });

  const artifactAudits: ArtifactTraceabilityRecord[] = [];
  let artifactsWithEvidence = 0;
  let artifactsWithoutEvidence = 0;

  // Process artifacts
  for (const artifact of intelligence.artifacts) {
    const artifactEvidence = evidenceAuditList.filter(ea => ea.artifactId === artifact.id);
    const evidenceIds = artifactEvidence.map(ea => ea.evidenceId);
    
    const findingIdsSet = new Set<string>();
    for (const ea of artifactEvidence) {
      for (const fId of ea.usedByFindingIds) {
        findingIdsSet.add(fId);
      }
    }
    const findingIds = Array.from(findingIdsSet);

    let coverageState: 'covered' | 'partially_covered' | 'no_evidence' | 'unknown' = 'unknown';
    
    if (evidenceIds.length === 0) {
      coverageState = 'no_evidence';
      artifactsWithoutEvidence++;
      unresolvedTraceabilityIssues.push(`Artifact ${artifact.id} yielded no extractable evidence.`);
    } else {
      artifactsWithEvidence++;
      
      const unusedArtifactEvidence = artifactEvidence.filter(ea => ea.usageState === 'unused');
      if (unusedArtifactEvidence.length > 0) {
        coverageState = 'partially_covered';
      } else {
        coverageState = 'covered';
      }
    }

    artifactAudits.push({
      artifactId: artifact.id,
      evidenceIds,
      findingIds,
      coverageState,
    });
  }

  return {
    summary: {
      totalFindings: intelligence.findings.length,
      findingsWithSupportingEvidence,
      findingsWithContradictingEvidence,
      findingsWithMissingEvidence,
      totalEvidenceItems: intelligence.evidence.length,
      evidenceUsedByFindings,
      unusedEvidenceItems,
      totalArtifacts: intelligence.artifacts.length,
      artifactsWithEvidence,
      artifactsWithoutEvidence,
    },
    findingAudits,
    evidenceAudits: evidenceAuditList,
    artifactAudits,
    unresolvedTraceabilityIssues,
  };
}
