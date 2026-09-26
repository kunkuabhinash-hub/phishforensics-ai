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

import { isImageArtifact, processImageArtifact } from './imageAnalyzer.ts';
import type { ProviderAnalysisResult } from './types.ts';
import type { EvidenceItem } from '../../../../shared/types/threat-intelligence.ts';

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

    // 1.5. Process image / screenshot artifacts via OCR and Vision Analysis
    for (const art of normalizedInput.artifacts) {
      if (isImageArtifact(art)) {
        await processImageArtifact(art);
      }
    }

    // Check for Image Processing / Vision Failure (Case B Fallback)
    const imageFailure = normalizedInput.artifacts.find(a => a.metadata?.imageProcessingFailure);
    if (imageFailure) {
      const failureReason = (imageFailure.metadata?.imageFailureReason as string) || 'Corrupt or unreadable image data';
      const fallbackEvidence: EvidenceItem[] = [
        {
          id: 'EV-001',
          type: 'other',
          artifactId: imageFailure.id,
          rawContent: `Image Processing Error: ${failureReason}`,
          defangedContent: `Image Processing Error: ${failureReason}`,
          location: 'Image Ingestion & Pre-processing',
          status: 'observed',
          description: `Image analysis failure: ${failureReason}`,
          confidence: 100,
        }
      ];

      const fallbackMapped: ProviderAnalysisResult = {
        suggestedVerdict: 'unknown',
        suggestedSeverity: 'unknown',
        suggestedRiskScore: null,
        confidenceScore: 15,
        summary: 'Image analysis could not extract sufficient readable evidence due to an image processing or decoding failure.',
        verdictJustification: `Image processing failure: ${failureReason}. The system could not extract readable visual or textual evidence from the uploaded artifact.`,
        findings: [],
        attackerIntent: {
          primaryObjective: 'Unknown — Processing Failure',
          secondaryObjectives: [],
          targetedAsset: 'Unknown',
          intendedVictimAction: 'Analysis could not proceed due to image processing failure.',
          potentialImpact: 'Unknown',
          supportingEvidenceIds: ['EV-001'],
          confidence: 0,
          uncertaintyNotes: 'Vision processing could not inspect image bytes.',
        },
        victimRequestedAction: {
          actionType: 'unknown',
          description: 'No observable victim action established.',
          urgencyLevel: 'unknown',
          targetChannel: 'unknown',
          confidence: 0,
          supportingEvidenceIds: ['EV-001'],
        },
        socialEngineering: [],
        attackDNAAttributes: [],
        reconstructionStages: [],
        unverifiedClaims: [],
        conflictingSignals: [],
        missingEvidence: [
          {
            missingItem: 'Valid readable image file',
            whyNeeded: 'Required for visual layout and OCR analysis',
            impactOnAnalysis: 'Completely blocks threat classification'
          }
        ],
        defensiveRecommendations: [],
        educationalExplanation: {
          whatHappened: 'An unreadable or corrupted image file was submitted for examination.',
          knownFacts: [],
          inferredAssumptions: [],
          unknownFactors: [],
          whyThisWorks: '',
          keySignalsNoticed: [],
          psychologicalMechanism: '',
          saferAlternativeBehavior: 'Ensure uploaded screenshots are clear and in supported formats (PNG, JPEG, WEBP).'
        },
        limitations: ['Image decoding failure prevented forensic inspection.'],
        assumptions: [],
        unresolvedQuestions: ['Why did image decoding fail?', 'Is the image truncated or in an unsupported format?'],
        nextInvestigationActions: [{ action: 'Re-upload image in standard PNG or JPEG format', reason: 'Allows OCR and visual forensic extraction' }]
      };

      const canonicalResult = assembleCanonicalResult(normalizedInput, fallbackEvidence, fallbackMapped);
      const validationAudit: ValidationAuditReport = {
        validationStatus: 'warnings_generated',
        warnings: [`Image processing failed for artifact ${imageFailure.id}: ${failureReason}`],
        invalidEvidenceReferences: [],
        invalidArtifactReferences: [],
      };

      return { canonicalResult, validationAudit };
    }
    
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
