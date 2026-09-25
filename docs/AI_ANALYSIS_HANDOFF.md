# AI Analysis Handoff

This document provides the definitive integration contract for the AI-driven threat analysis subsystem. 

## 1. Integration Entry Point

The primary entry point for backend integrations is:

```typescript
import { runFullInvestigation } from 'backend/src/services/ai-threat-analysis/integrationContract.ts';

const result = await runFullInvestigation(
  rawInputs: RawArtifactInput | RawArtifactInput[],
  options?: AnalysisInputOptions,
  crossInvestigationExplanations?: CrossInvestigationPatternExplanation[]
);
```

This single function executes the complete pipeline:
1. Normalization & Evidence Extraction
2. Secure AI Provider execution
3. Hallucination Guard Validation
4. Canonical Intelligence Assembly
5. Analyst Investigation View Projection
6. Analyst Intelligence Brief Projection

## 2. Input Contract

The pipeline accepts one or more raw artifacts:

```typescript
export interface RawArtifactInput {
  id?: string;
  type: 'raw_email' | 'url' | 'domain' | 'ip' | 'file';
  content: string;
  name?: string;
  format?: string;
  metadata?: Record<string, string | number | boolean>;
}
```

## 3. Output Contract

`runFullInvestigation` returns a `FullInvestigationResult` with three distinct layers.

- **`canonical` (`CanonicalThreatIntelligence`)**: The immutable single source of truth containing all base observations, intelligence, validations, and missing states. 
- **`analystView` (`AnalystInvestigationView`)**: A fully deterministic projection layer containing read-only intelligence mappings like `findingExplanations`, `attackDNA`, `traceabilityAudit`, and `crossArtifactCorrelations`.
- **`intelligenceBrief` (`AnalystIntelligenceBrief`)**: A high-level, frontend-ready dashboard summary constructed entirely from canonical truth. Includes dynamically generated executive summaries and deduplicated next actions.

## 4. Evidence Lineage

All intelligence must trace back to concrete evidence. The lineage flows strictly as:

**Artifact** → **EvidenceItem** → **FindingItem / AttackDNA / Reconstruction** → **Explanation / Brief**

The system structurally enforces this:
- `EvidenceItem` carries an `artifactId` back-reference.
- `FindingItem` holds `supportingEvidenceIds` mapping to specific `EvidenceItem.id`.
- The `TraceabilityAudit` automatically cross-references these IDs to guarantee there are no hallucinated links.

## 5. Unknown and Uncertainty Semantics

Consumers **must** respect the uncertainty semantics explicitly:
- `unknown` / `null`: Values for verdicts, severities, or risk scores will remain explicitly `unknown` or `null` if the AI cannot determine them. Do not cast these to defaults like `0` or `benign`.
- `inferred`: Means the AI has logically deduced something that was not explicitly present in the evidence.
- `unverified`: Means a claim exists (e.g., attribution) but cannot be corroborated by the current evidence.
- `conflicted`: Represents contradictory evidence paths. The frontend must preserve these conflicts rather than forcing a deterministic conclusion.
- `missing_evidence`: Defines what telemetry is needed to reach a higher-confidence conclusion.

## 6. AI Provider Boundary

The AI provider implementation (e.g., Gemini) is securely isolated behind `ThreatAnalysisProvider`.
- The canonical contracts and outputs are entirely provider-neutral. 
- You must **never** write frontend or backend integration code that assumes Gemini-specific JSON structures, metadata, or model quirks.

## 7. Frontend Consumption Guide

The frontend must use the existing projection layers to populate its views. **Do not write new intelligence logic in the frontend.**

- **Dashboard summary** → Use `intelligenceBrief.executiveSummary` and `intelligenceBrief.threatAssessmentSummary`.
- **Evidence panel** → Use `canonical.evidence` and `intelligenceBrief.evidenceHighlights`.
- **Findings panel** → Use `intelligenceBrief.keyFindings` (which wraps `FindingExplanation`s).
- **Attack DNA** → Use `intelligenceBrief.attackerBehaviorSummary` (or `analystView.attackDNA`).
- **Reconstruction** → Use `intelligenceBrief.reconstructionSummary`.
- **Timeline** → Use `canonical.investigationTimeline` for observed chronological events.
- **Uncertainty** → Use `intelligenceBrief.uncertaintySummary` for limitations, unverified claims, and conflicting signals.
- **Recommendations** → Use `intelligenceBrief.recommendedNextActions` (which explicitly labels sources like `missing_evidence` or `quality_warning`).
- **Traceability** → Use `intelligenceBrief.traceabilitySummary`.

## 8. Security Constraints

Downstream modules (backend controllers / frontend rendering) **MUST NOT**:
- Make active network calls (no DNS lookups, no URL fetching).
- Execute file contents or attachments.
- Construct deployable phishing material.
- Attribute intelligence to specific threat actors.
- Mutate the `CanonicalThreatIntelligence` state.

## 9. Integration Rules

- **No duplicate intelligence schemas**: Consume only from `shared/types/threat-intelligence.ts`.
- **No hardcoded verdicts/risk values**: Do not fallback to manual threat scores if the AI returns `null` or `unknown`.
- **No duplicate analysis server**: Consume from `runFullInvestigation`.
- **Preserve evidence IDs**: Do not regenerate IDs downstream.
- **Treat AI output as untrusted**: Rely solely on the validated `canonical` result output, never the raw provider output.

## 10. Current Limitations

- **State Persistence**: The layer does not persist data to the database; it is purely a functional pipeline. The backend is responsible for storing the `FullInvestigationResult`.
- **Cross-Investigation Retrieval**: The pipeline natively supports comparing historical investigations, but it relies on the backend to provide the existing canonical intelligence context via `crossInvestigationExplanations` during invocation.
