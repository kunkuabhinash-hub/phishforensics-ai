import type { EvidenceItem } from '../../../../shared/types/threat-intelligence.ts';
import type { ThreatAnalysisProvider, NormalizedAnalysisInput } from './types.ts';
import type { AIReasoningResult } from './reasoningSchema.ts';

export class FoundationPassThroughProvider implements ThreatAnalysisProvider {
  public readonly providerId = 'foundation-passthrough-provider';
  public readonly providerVersion = '2.0.0';

  public async analyze(
    input: NormalizedAnalysisInput,
    extractedEvidence: EvidenceItem[],
    systemInstructions: string,
    analysisPrompt: string
  ): Promise<Partial<AIReasoningResult>> {
    const hasEvidence = extractedEvidence.length > 0;

    return {
      suggestedVerdict: hasEvidence ? 'suspicious' : 'unknown',
      suggestedSeverity: hasEvidence ? 'medium' : 'unknown',
      suggestedRiskScore: hasEvidence ? 50 : null,
      confidenceScore: hasEvidence ? 60 : 0,
      summary: hasEvidence
        ? `Found ${extractedEvidence.length} candidate evidence item(s) across ${input.artifacts.length} artifact(s).`
        : 'Insufficient evidence to form a definitive verdict.',
      verdictJustification: hasEvidence
        ? 'Pass-through foundation engine identified candidate indicators for analysis.'
        : 'No observable indicators extracted from submitted input.',
      findings: extractedEvidence.map((e) => ({
        category: `candidate_${e.type}`,
        title: `Candidate ${e.type.toUpperCase()} Observed`,
        description: e.description,
        supportingEvidenceIds: [e.id],
        confidence: e.confidence || 70,
        status: e.status === 'observed' ? 'observed' : 'inferred',
        severity: 'medium',
        impact: `Observable ${e.type} requires threat analysis evaluation.`,
      })),
      attackerIntent: {
        primaryObjective: hasEvidence ? 'Under Evaluation — Pending Provider Ingest' : 'Unknown — Insufficient Evidence',
        secondaryObjectives: [],
        targetedAsset: 'Under Investigation',
        intendedVictimAction: 'Under Investigation',
        potentialImpact: 'Under Investigation',
        supportingEvidenceIds: extractedEvidence.map((e) => e.id),
        confidence: hasEvidence ? 40 : 0,
        uncertaintyNotes: 'Attacker intent is unverified prior to AI provider evaluation.',
      },
      socialEngineering: [],
      attackDNAAttributes: [],
      reconstructionStages: [],
      unverifiedClaims: [],
      conflictingSignals: [],
      missingEvidence: [],
      defensiveRecommendations: [],
      educationalExplanation: {
        whatHappened: 'Artifact was normalized and parsed for observable indicators.',
        whyThisWorks: 'Attackers craft artifacts to deceive victims using subtle social engineering or technical spoofing.',
        psychologicalMechanism: 'Under Evaluation',
        saferAlternativeBehavior: 'Always verify suspicious communications independently.',
      },
      limitations: ['Executed using Foundation PassThrough Provider without live LLM inference.'],
      assumptions: ['Extracted evidence represents verbatim artifact elements.'],
    };
  }
}
