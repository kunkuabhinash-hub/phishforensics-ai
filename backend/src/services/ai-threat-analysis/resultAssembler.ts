import type {
  CanonicalThreatIntelligence,
  EvidenceItem,
  FindingItem,
  SubmittedArtifact,
  AttackerIntent,
  VictimRequestedAction,
  SocialEngineeringTechnique,
  TechnicalIndicator,
  AttackDNASource,
  ReconstructionStage,
  UncertaintyReport,
  MissingEvidenceItem,
  DefensiveRecommendation,
  EducationalExplanation,
  AnalysisLimitations,
  TimelineEvent,
  ThreatAssessment,
  EvidenceGraph,
  GraphNode,
  GraphRelationship,
} from '../../../../shared/types/threat-intelligence.ts';
import type { NormalizedAnalysisInput, ProviderAnalysisResult } from './types.ts';
import { defangUrl, defangEmail } from './safety.ts';

export function assembleCanonicalResult(
  input: NormalizedAnalysisInput,
  evidence: EvidenceItem[],
  providerResult?: ProviderAnalysisResult
): CanonicalThreatIntelligence {
  const schemaVersion = '1.0.0';
  const analyzerVersion = '1.0.0-foundation';

  const submittedArtifacts: SubmittedArtifact[] = input.artifacts.map((art) => ({
    id: art.id,
    type: art.type,
    name: art.name,
    format: art.format,
    sizeBytes: art.sizeBytes,
    sha256: art.sha256,
    receivedAt: input.timestamp,
    metadata: art.metadata,
  }));

  // Missing evidence is dynamically inferred by the AI reasoning engine.
  // We do not hardcode universal lists based on simple presence/absence checks.
  const missingEvidence: MissingEvidenceItem[] = (providerResult?.missingEvidence || []).map((m, idx) => ({ 
    ...m, 
    id: `MISSING-PROV-${idx + 1}` 
  }));

  const rawFindings = providerResult?.findings || [];
  const findings: FindingItem[] = rawFindings.map((f, idx) => ({
    ...f,
    id: `FIND-${(idx + 1).toString().padStart(3, '0')}`,
    supportingEvidenceIds: f.supportingEvidenceIds || evidence.map((e) => e.id),
  }));

  const attackerIntent: AttackerIntent = providerResult?.attackerIntent
    ? {
        ...providerResult.attackerIntent,
        supportingEvidenceIds: providerResult.attackerIntent.supportingEvidenceIds || [],
        supportingFindingIds: providerResult.attackerIntent.supportingFindingIds || findings.map((f) => f.id),
      }
    : {
        primaryObjective: evidence.length > 0 ? 'Undetermined — Pending Deeper Evidence' : 'Unknown — Insufficient Evidence Supplied',
        secondaryObjectives: [],
        targetedAsset: 'Unknown',
        intendedVictimAction: 'Unknown',
        potentialImpact: 'Unknown',
        supportingEvidenceIds: [],
        supportingFindingIds: [],
        confidence: 0,
        uncertaintyNotes: 'Insufficient evidence to establish attacker intent with confidence.',
      };

  const victimRequestedAction: VictimRequestedAction = providerResult?.victimRequestedAction || {
    actionType: 'unknown',
    description: 'No explicit requested victim action established.',
    urgencyLevel: 'unknown',
    targetChannel: 'unknown',
    supportingEvidenceIds: evidence.map((e) => e.id),
    confidence: 0,
  };

  const socialEngineering: SocialEngineeringTechnique[] = (providerResult?.socialEngineering || []).map((se, idx) => ({
    ...se,
    id: `SE-${(idx + 1).toString().padStart(3, '0')}`,
  }));

  const technicalIndicators: TechnicalIndicator[] = [];
  let iocCounter = 0;

  for (const art of input.artifacts) {
    for (const sender of art.extractedSenders) {
      iocCounter++;
      technicalIndicators.push({
        id: `IOC-${iocCounter.toString().padStart(3, '0')}`,
        type: 'sender',
        value: sender,
        defangedValue: defangEmail(sender),
        context: `Sender from artifact ${art.id}`,
        supportingEvidenceIds: evidence.filter((e) => e.type === 'sender').map((e) => e.id),
        suspicionLevel: 'unknown',
      });
    }

    for (const url of art.extractedUrls) {
      iocCounter++;
      technicalIndicators.push({
        id: `IOC-${iocCounter.toString().padStart(3, '0')}`,
        type: 'url',
        value: url,
        defangedValue: defangUrl(url),
        context: `URL extracted from artifact ${art.id}`,
        supportingEvidenceIds: evidence.filter((e) => e.type === 'url').map((e) => e.id),
        suspicionLevel: 'unknown',
      });
    }
  }

  const attackDNASource: AttackDNASource = {
    attributes: (providerResult?.attackDNAAttributes || []).map((attr, idx) => ({
      ...attr,
      id: `DNA-ATTR-${(idx + 1).toString().padStart(3, '0')}`,
    })),
  };

  const reconstructionTimeline: ReconstructionStage[] = (providerResult?.reconstructionStages || []).map((stg, idx) => ({
    ...stg,
    stageId: `STAGE-${(idx + 1).toString().padStart(3, '0')}`,
    order: idx + 1,
    supportingFindingIds: stg.supportingFindingIds || findings.map((f) => f.id),
  }));

  const threatAssessment: ThreatAssessment = {
    verdict: providerResult?.suggestedVerdict || (evidence.length === 0 ? 'unknown' : 'suspicious'),
    severity: providerResult?.suggestedSeverity || (evidence.length === 0 ? 'unknown' : 'medium'),
    riskScore: providerResult?.suggestedRiskScore !== undefined ? providerResult.suggestedRiskScore : null,
    confidenceScore: providerResult?.confidenceScore ?? (evidence.length > 0 ? 50 : 0),
    summary: providerResult?.summary || 'Analysis foundation assembled candidate evidence for inspection.',
    verdictJustification: providerResult?.verdictJustification || 'Verdict derived from candidate evidence analysis.',
  };

  const uncertaintyReport: UncertaintyReport = {
    overallUncertaintyNotes:
      evidence.length === 0
        ? 'No observable evidence items were extracted from the submitted artifact.'
        : 'Analysis completed with baseline candidate evidence. Unverified claims require additional context.',
    unverifiedClaims: providerResult?.unverifiedClaims || [],
    conflictingSignals: providerResult?.conflictingSignals || [],
  };

  const defensiveRecommendations: DefensiveRecommendation[] = (providerResult?.defensiveRecommendations || []).map((rec, idx) => ({
    ...rec,
    id: `REC-${(idx + 1).toString().padStart(3, '0')}`,
  }));

  const educationalExplanation: EducationalExplanation = providerResult?.educationalExplanation || {
    whatHappened: 'A suspicious artifact was submitted for forensic examination.',
    knownFacts: [],
    inferredAssumptions: [],
    unknownFactors: [],
    whyThisWorks: 'Attackers exploit cognitive biases such as trust, urgency, or authority to bypass human scrutiny.',
    keySignalsNoticed: evidence.map((e) => e.description),
    psychologicalMechanism: 'Generic Psychological Influence',
    saferAlternativeBehavior: 'Always verify unexpected communications through out-of-band channels.',
  };

  const analysisLimitations: AnalysisLimitations = {
    limitations: providerResult?.limitations || [],
    assumptionsMade: providerResult?.assumptions || [],
  };

  const investigationTimeline: TimelineEvent[] = [
    {
      id: 'EVT-001',
      timestamp: input.timestamp,
      timestampProvenance: 'Investigation Engine',
      title: 'Artifact Ingested',
      description: `Ingested ${input.artifacts.length} artifact(s) for investigation`,
      eventType: 'observed_artifact',
      supportingEvidenceIds: [],
      artifactIds: input.artifacts.map(a => a.id),
      confidence: 100,
      status: 'observed',
    },
    ...evidence.map((e, idx) => ({
      id: `EVT-${(idx + 2).toString().padStart(3, '0')}`,
      timestamp: (e.metadata?.timestamp as string) || undefined, // Use explicit undefined if missing, to represent unknown timing
      timestampProvenance: e.metadata?.timestamp ? e.location : undefined,
      title: `Evidence Observed: ${e.type}`,
      description: e.description,
      eventType: 'detected_tactic' as const,
      supportingEvidenceIds: [e.id],
      artifactIds: e.artifactId ? [e.artifactId] : [],
      confidence: e.confidence || 80,
      status: e.metadata?.timestamp ? (e.status === 'observed' ? 'observed' : 'inferred') : 'unknown',
    })),
  ];

  const attackNarrative = providerResult?.attackNarrative || {
    initialSignal: 'Unknown',
    socialEngineeringMechanism: 'Unknown',
    requestedVictimAction: 'Unknown',
    technicalCharacteristics: 'Unknown',
    defensiveReconstruction: 'Unknown',
    unknownFactors: [],
  };

  // ==========================================================================
  // CROSS-ARTIFACT CORRELATION (Deterministic + AI Assessed)
  // ==========================================================================
  
  const crossArtifactCorrelations: import('../../../../shared/types/threat-intelligence.ts').CrossArtifactCorrelation[] = [];
  let corrCounter = 1;
  const generateCorrId = () => `CORR-${corrCounter.toString().padStart(3, '0')}`;
  
  // 1. Deterministic Correlation
  // E.g., shared URLs or senders across different artifacts
  const evidenceByType = new Map<string, typeof evidence>();
  for (const ev of evidence) {
    if (!ev.artifactId) continue;
    const key = `${ev.type}:${ev.rawContent.toLowerCase()}`;
    if (!evidenceByType.has(key)) evidenceByType.set(key, []);
    evidenceByType.get(key)!.push(ev);
  }

  for (const [key, sharedEvs] of evidenceByType.entries()) {
    const uniqueArtifactIds = Array.from(new Set(sharedEvs.map(e => e.artifactId)));
    if (uniqueArtifactIds.length > 1) {
      // We have a cross-artifact correlation!
      const type = key.startsWith('url:') ? 'shared_url' : key.startsWith('sender:') ? 'shared_sender' : 'shared_text_indicator';
      crossArtifactCorrelations.push({
        id: generateCorrId(),
        artifactIds: uniqueArtifactIds as string[],
        supportingEvidenceIds: sharedEvs.map(e => e.id),
        relationshipType: type,
        explanation: `Deterministic match found for ${key.split(':')[0]} "${sharedEvs[0].rawContent}" across multiple artifacts.`,
        status: 'observed',
      });
      corrCounter++;
    }
  }

  // 2. AI Assessed Correlation (append and ensure unique IDs)
  if (providerResult?.crossArtifactCorrelations) {
    for (const aiCorr of providerResult.crossArtifactCorrelations) {
      if (aiCorr.artifactIds.length > 1) {
        crossArtifactCorrelations.push({
          id: generateCorrId(),
          artifactIds: aiCorr.artifactIds,
          supportingEvidenceIds: aiCorr.supportingEvidenceIds,
          relationshipType: aiCorr.relationshipType,
          explanation: aiCorr.explanation,
          status: aiCorr.status,
        });
        corrCounter++;
      }
    }
  }

  // ==========================================================================
  // GRAPH CONSTRUCTION (Deterministic, Post-Validation)
  // ==========================================================================

  const nodes: GraphNode[] = [];
  const relationships: GraphRelationship[] = [];
  let relCounter = 1;

  const addRel = (fromNodeId: string, toNodeId: string, relationshipType: GraphRelationshipType) => {
    relationships.push({
      id: `REL-${relCounter.toString().padStart(4, '0')}`,
      fromNodeId,
      toNodeId,
      relationshipType,
    });
    relCounter++;
  };

  // 1. Artifacts
  for (const artifact of submittedArtifacts) {
    nodes.push({ id: artifact.id, type: 'artifact', label: `Artifact: ${artifact.type}` });
  }

  // 2. Evidence
  for (const ev of evidence) {
    nodes.push({ id: ev.id, type: 'evidence', label: `Evidence: ${ev.type}`, status: ev.status });
    if (ev.artifactId) {
      addRel(ev.artifactId, ev.id, 'artifact_contains_evidence');
    }
  }

  // 3. Findings
  for (const finding of findings) {
    nodes.push({ id: finding.id, type: 'finding', label: finding.title, status: finding.status });
    for (const evId of finding.supportingEvidenceIds) {
      addRel(evId, finding.id, 'evidence_supports_finding');
    }
    if (finding.contradictingEvidenceIds) {
      for (const evId of finding.contradictingEvidenceIds) {
        addRel(evId, finding.id, 'evidence_contradicts_finding');
      }
    }
  }

  // 4. Attack DNA
  for (const dna of attackDNASource.attributes) {
    nodes.push({ id: dna.id, type: 'attack_dna', label: `DNA: ${dna.characteristic}`, status: dna.status });
    for (const evId of dna.supportingEvidenceIds) {
      addRel(evId, dna.id, 'evidence_supports_attack_dna');
    }
  }

  // 5. Reconstruction Stages
  for (const stg of reconstructionTimeline) {
    nodes.push({ id: stg.stageId, type: 'reconstruction_stage', label: stg.stageName, status: stg.status });
    for (const findId of stg.supportingFindingIds) {
      addRel(findId, stg.stageId, 'finding_supports_reconstruction');
    }
  }

  // 6. Defensive Recommendations
  for (const rec of defensiveRecommendations) {
    nodes.push({ id: rec.id, type: 'recommendation', label: rec.title });
    for (const evId of rec.supportingEvidenceIds) {
      addRel(evId, rec.id, 'evidence_supports_recommendation');
    }
    for (const findId of rec.supportingFindingIds) {
      addRel(findId, rec.id, 'finding_supports_recommendation');
    }
  }

  // 7. Conflicting Signals
  for (const conflict of uncertaintyReport.conflictingSignals) {
    // If the conflicting signal text matches an evidence ID, we could map it, 
    // but the schema implies signalA and signalB are descriptive strings. 
    // If we wanted to map them, we'd need IDs. For now, we only map 'evidence_contradicts_finding' 
    // if we had structured conflicting evidence. The user requested:
    // "If the existing model has a better conflict representation, reuse it."
    // We will leave Conflicting Signals in the UncertaintyReport for now, as there's no direct node to link them to easily without parsing prose.
  }
  
  // 8. Cross-Artifact Correlations
  for (const corr of crossArtifactCorrelations) {
    // Treat correlation as a node
    nodes.push({ id: corr.id, type: 'finding', label: `Correlation: ${corr.relationshipType}`, status: corr.status });
    
    for (const evId of corr.supportingEvidenceIds) {
      addRel(evId, corr.id, 'evidence_supports_finding'); // Conceptual mapping to a finding-like node
    }
  }

  // ==========================================================================
  // INVESTIGATION QUALITY (Deterministic Calculation)
  // ==========================================================================
  
  const analystWarnings: string[] = [];
  let completenessStatus: 'strong' | 'partial' | 'weak' | 'unknown' = 'unknown';

  if (evidence.length === 0) {
    analystWarnings.push('No verifiable evidence was extracted from the artifacts.');
    completenessStatus = 'weak';
  } else if (evidence.length < 3) {
    completenessStatus = 'partial';
  } else {
    completenessStatus = 'strong';
  }

  const unsupportedFindings = findings.filter(f => f.supportingEvidenceIds.length === 0);
  if (unsupportedFindings.length > 0) {
    analystWarnings.push(`${unsupportedFindings.length} findings lack direct evidence support.`);
    if (completenessStatus === 'strong') completenessStatus = 'partial';
  }

  if (uncertaintyReport.conflictingSignals.length > 0) {
    analystWarnings.push(`There are ${uncertaintyReport.conflictingSignals.length} conflicting signals in the evidence.`);
  }

  if (missingEvidence.length > 0) {
    analystWarnings.push(`Missing ${missingEvidence.length} critical evidence items.`);
    if (completenessStatus === 'strong') completenessStatus = 'partial';
  }

  if (providerResult?.unresolvedQuestions?.length) {
    if (completenessStatus === 'strong') completenessStatus = 'partial';
  }
  
  if (crossArtifactCorrelations.length > 0 && completenessStatus !== 'strong') {
    // Cross-artifact correlation strengthens the investigation
    completenessStatus = 'strong';
  }

  const evidenceCoverage = evidence.length > 0 
    ? (evidence.length > 5 ? 'High coverage with multiple evidence points' : 'Moderate coverage with limited evidence points')
    : 'No evidence coverage';

  const findingSupportCoverage = unsupportedFindings.length === 0 
    ? 'All findings are supported by evidence.' 
    : 'Some findings lack supporting evidence and rely on inference.';

  const investigationQuality = {
    evidenceCoverage,
    findingSupportCoverage,
    unresolvedQuestions: providerResult?.unresolvedQuestions || [],
    nextInvestigationActions: providerResult?.nextInvestigationActions || [],
    analystWarnings,
    completenessStatus,
  };

  return {
    investigation: {
      id: input.investigationId,
      timestamp: input.timestamp,
      schemaVersion,
      analyzerVersion,
      status: 'completed',
    },
    artifacts: submittedArtifacts,
    threatAssessment,
    evidence,
    findings,
    attackerIntent,
    victimRequestedAction,
    socialEngineering,
    technicalIndicators,
    attackDNASource,
    reconstructionTimeline,
    uncertaintyReport,
    missingEvidence,
    investigationQuality,
    defensiveRecommendations,
    educationalExplanation,
    analysisLimitations,
    investigationTimeline,
    attackNarrative,
    crossArtifactCorrelations,
    evidenceGraph: {
      nodes,
      relationships,
    }
  };
}
