import type { CanonicalThreatIntelligence } from '../../../../shared/types/threat-intelligence.ts';
import type {
  RawArtifactInput,
  AnalysisInputOptions,
  ThreatAnalysisProvider,
  AnalysisAuditRecord,
  ValidationAuditReport,
} from './types.ts';
import { normalizeAnalysisInput } from './normalizer.ts';
import { extractCandidateEvidence } from './evidenceExtractor.ts';
import { assembleCanonicalResult } from './resultAssembler.ts';
import { FoundationPassThroughProvider } from './providerInterface.ts';
import { computeHash, assertPassiveOnly } from './safety.ts';
import { buildSystemInstructions, buildAnalysisPrompt } from './promptBuilder.ts';
import { validateAndMapReasoning } from './reasoningValidator.ts';

import { resolveProvider } from './providerFactory.ts';

export class ThreatAnalysisPipeline {
  private provider: ThreatAnalysisProvider;

  constructor(provider?: ThreatAnalysisProvider) {
    // Defers to the factory to load the configured provider dynamically
    this.provider = provider || resolveProvider();
  }

  public setProvider(provider: ThreatAnalysisProvider): void {
    this.provider = provider;
  }

  public async analyze(
    rawInputs: RawArtifactInput | RawArtifactInput[],
    options: AnalysisInputOptions = {}
  ): Promise<{ canonicalResult: CanonicalThreatIntelligence; validationAudit: ValidationAuditReport }> {
    assertPassiveOnly('Threat Analysis Pipeline Execution');

    // 1. Normalize
    const normalizedInput = normalizeAnalysisInput(rawInputs, options);
    
    // 2. Extract deterministic evidence
    const extractedEvidence = extractCandidateEvidence(normalizedInput);
    
    // 3. Build reasoning instructions
    const systemInstructions = buildSystemInstructions();
    const analysisPrompt = buildAnalysisPrompt(normalizedInput, extractedEvidence);
    
    // 4. Call provider boundary (Live reasoning execution)
    const rawReasoning = await this.provider.analyze(
      normalizedInput,
      extractedEvidence,
      systemInstructions,
      analysisPrompt
    );
    
    // 5. Validate AI reasoning and apply hallucination guards
    const { mappedResult, validationAudit } = validateAndMapReasoning(
      rawReasoning,
      extractedEvidence,
      normalizedInput.artifacts
    );
    
    // 6. Assemble into canonical output
    const canonicalResult = assembleCanonicalResult(normalizedInput, extractedEvidence, mappedResult);

    return { canonicalResult, validationAudit };
  }

  public async analyzeWithAudit(
    rawInputs: RawArtifactInput | RawArtifactInput[],
    options: AnalysisInputOptions = {}
  ): Promise<{ canonicalResult: CanonicalThreatIntelligence; auditRecord: AnalysisAuditRecord }> {
    const { canonicalResult, validationAudit } = await this.analyze(rawInputs, options);
    const rawContentConcatenated = canonicalResult.artifacts.map((a) => a.sha256).join(':');

    const auditRecord: AnalysisAuditRecord = {
      auditId: `AUDIT-${Date.now().toString(36).toUpperCase()}`,
      investigationId: canonicalResult.investigation.id,
      timestamp: canonicalResult.investigation.timestamp,
      inputSha256: computeHash(rawContentConcatenated),
      extractorVersion: '1.0.0-foundation',
      providerId: this.provider.providerId,
      providerVersion: this.provider.providerVersion,
      schemaVersion: canonicalResult.investigation.schemaVersion,
      validationAudit,
      canonicalOutput: canonicalResult,
    };

    return { canonicalResult, auditRecord };
  }
}
