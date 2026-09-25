import type {
  ArtifactType,
  CanonicalThreatIntelligence,
  EvidenceItem,
  FindingItem,
  AttackerIntent,
  SocialEngineeringTechnique,
  AttackDNAAttribute,
  ReconstructionStage,
  DefensiveRecommendation,
  EducationalExplanation,
  MissingEvidenceItem,
  UnverifiedClaim,
  ConflictingSignal,
  ThreatVerdict,
  ThreatSeverity,
} from '../../../../shared/types/threat-intelligence.ts';
import type { AIReasoningResult } from './reasoningSchema.ts';

export interface RawArtifactInput {
  id?: string;
  type: ArtifactType;
  content: string;
  name?: string;
  format?: string;
  metadata?: Record<string, string | number | boolean>;
}

export interface AnalysisInputOptions {
  investigationId?: string;
  allowInferences?: boolean;
  userContext?: string;
}

export interface NormalizedArtifact {
  id: string;
  type: ArtifactType;
  name?: string;
  format?: string;
  sha256: string;
  sizeBytes: number;
  rawContent: string;
  sanitizedContent: string;
  extractedHeaders?: Record<string, string>;
  extractedUrls: string[];
  extractedDomains: string[];
  extractedSenders: string[];
  metadata: Record<string, string | number | boolean>;
}

export interface NormalizedAnalysisInput {
  investigationId: string;
  timestamp: string;
  artifacts: NormalizedArtifact[];
  options: AnalysisInputOptions;
}

export interface ProviderAnalysisResult {
  suggestedVerdict?: ThreatVerdict;
  suggestedSeverity?: ThreatSeverity;
  suggestedRiskScore?: number | null;
  confidenceScore: number;
  summary: string;
  verdictJustification: string;
  findings: Omit<FindingItem, 'id'>[];
  attackerIntent: Omit<AttackerIntent, 'confidence'> & { confidence: number };
  victimRequestedAction: VictimRequestedAction;
  socialEngineering: Omit<SocialEngineeringTechnique, 'id'>[];
  attackDNAAttributes: Omit<AttackDNAAttribute, 'id'>[];
  reconstructionStages: Omit<ReconstructionStage, 'stageId'>[];
  unverifiedClaims: UnverifiedClaim[];
  conflictingSignals: ConflictingSignal[];
  missingEvidence: Omit<MissingEvidenceItem, 'id'>[];
  defensiveRecommendations: Omit<DefensiveRecommendation, 'id'>[];
  educationalExplanation: EducationalExplanation;
  limitations: string[];
  assumptions: string[];
}

export interface ValidationAuditReport {
  validationStatus: 'success' | 'warnings_generated' | 'failed';
  warnings: string[];
  invalidEvidenceReferences: string[];
  invalidArtifactReferences: string[];
}

export interface ThreatAnalysisProvider {
  readonly providerId: string;
  readonly providerVersion: string;

  analyze(
    input: NormalizedAnalysisInput,
    extractedEvidence: EvidenceItem[],
    systemInstructions: string,
    analysisPrompt: string
  ): Promise<Partial<AIReasoningResult>>;
}

export interface AnalysisAuditRecord {
  auditId: string;
  investigationId: string;
  timestamp: string;
  inputSha256: string;
  extractorVersion: string;
  providerId: string;
  providerVersion: string;
  schemaVersion: string;
  validationAudit: ValidationAuditReport;
  canonicalOutput: CanonicalThreatIntelligence;
}
