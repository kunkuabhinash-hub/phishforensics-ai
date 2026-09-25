import type { ThreatVerdict, ThreatSeverity } from '../../../../shared/types/threat-intelligence.ts';

/**
 * ============================================================================
 * PHISHFORENSICS AI — AI REASONING SCHEMA
 * ============================================================================
 *
 * This defines the exact JSON structure the AI model is instructed to generate.
 * It is provider-neutral (agnostic to Gemini/OpenAI/Claude) and acts as the
 * reasoning contract before validation.
 */

export interface AIReasoningFinding {
  category: string;
  title: string;
  description: string;
  supportingEvidenceIds: string[];
  contradictingEvidenceIds?: string[];
  confidence: number;
  status: 'observed' | 'inferred' | 'unverified';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  impact: string;
}

export interface AIReasoningAttackerIntent {
  primaryObjective: string;
  secondaryObjectives: string[];
  targetedAsset: string;
  intendedVictimAction: string;
  potentialImpact: string;
  supportingEvidenceIds: string[];
  confidence: number;
  uncertaintyNotes: string | null;
}

export interface AIReasoningSocialEngineering {
  techniqueName: string;
  explanation: string;
  supportingEvidenceIds: string[];
  confidence: number;
  status: 'observed' | 'inferred';
}

export interface AIReasoningAttackDNAAttribute {
  category: string;
  characteristic: string;
  value: string;
  supportingEvidenceIds: string[];
  status: 'observed' | 'inferred' | 'unverified' | 'unknown';
  confidence: number;
  explanation: string;
}

export interface AIReasoningReconstructionStage {
  stageName: string;
  description: string;
  supportingEvidenceIds: string[];
  confidence: number;
  status: 'observed' | 'inferred' | 'unverified' | 'unknown';
  victimAction?: string;
  safeConsequence?: string;
  uncertaintyNotes?: string;
}

export interface AIReasoningMissingEvidence {
  missingItem: string;
  whyNeeded: string;
  impactOnAnalysis: string;
}

export interface AIReasoningDefensiveRecommendation {
  priority: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  action: string;
  rationale: string;
  supportingEvidenceIds: string[];
  safeNextStep: string;
}

export interface AIReasoningEducationalExplanation {
  whatHappened: string;
  knownFacts: string[];
  inferredAssumptions: string[];
  unknownFactors: string[];
  whyThisWorks: string;
  psychologicalMechanism: string;
  saferAlternativeBehavior: string;
}

export interface AIReasoningUnverifiedClaim {
  claim: string;
  reasonUnverified: string;
  evidenceIds: string[];
}

export interface AIReasoningConflictingSignal {
  signalA: string;
  signalB: string;
  explanation: string;
}

export interface AIVictimRequestedAction {
  actionType: string;
  description: string;
  urgencyLevel: 'high' | 'medium' | 'low' | 'none' | 'unknown';
  targetChannel: string;
  supportingEvidenceIds: string[];
  confidence: number;
}

export interface AIReasoningAttackNarrative {
  initialSignal: string;
  socialEngineeringMechanism: string;
  requestedVictimAction: string;
  technicalCharacteristics: string;
  defensiveReconstruction: string;
  unknownFactors: string[];
}

export interface AIReasoningNextInvestigationAction {
  action: string;
  reason: string;
}

export interface AIReasoningCrossArtifactCorrelation {
  artifactIds: string[];
  supportingEvidenceIds: string[];
  relationshipType: 'shared_sender' | 'shared_domain' | 'shared_url' | 'shared_header_indicator' | 'shared_text_indicator' | 'temporal_relationship' | 'supporting_context' | 'contradicting_context' | 'unknown_relationship';
  explanation: string;
  status: 'observed' | 'inferred' | 'unverified' | 'unknown';
}

export interface AIReasoningResult {
  suggestedVerdict: ThreatVerdict | null;
  suggestedSeverity: ThreatSeverity | null;
  suggestedRiskScore: number | null;
  confidenceScore: number | null;
  summary: string;
  verdictJustification: string;
  
  findings: AIReasoningFinding[];
  attackerIntent: AIReasoningAttackerIntent;
  victimRequestedAction: AIVictimRequestedAction;
  socialEngineering: AIReasoningSocialEngineering[];
  attackDNAAttributes: AIReasoningAttackDNAAttribute[];
  reconstructionStages: AIReasoningReconstructionStage[];
  crossArtifactCorrelations: AIReasoningCrossArtifactCorrelation[];
  
  unverifiedClaims: AIReasoningUnverifiedClaim[];
  conflictingSignals: AIReasoningConflictingSignal[];
  missingEvidence: AIReasoningMissingEvidence[];
  
  unresolvedQuestions: string[];
  nextInvestigationActions: AIReasoningNextInvestigationAction[];
  
  defensiveRecommendations: AIReasoningDefensiveRecommendation[];
  educationalExplanation: AIReasoningEducationalExplanation;
  attackNarrative: AIReasoningAttackNarrative;
  
  limitations: string[];
  assumptions: string[];
}
