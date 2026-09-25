/**
 * PhishForensics AI - Complete Reconstruction Result Contract
 * 
 * Top-level unified contract combining:
 * Threat Analysis + Attack DNA + Attack Reconstruction + Safe Simulation + Safety Guidance.
 * 
 * Fully serializable to/from JSON for seamless transport across:
 * AI Threat Analysis -> Backend -> Attack Reconstruction -> Safe Simulation -> Frontend.
 */

import type { ThreatAnalysisInput } from "./threat-analysis";
import type { AttackDNA } from "./attack-dna";
import type { AttackReconstruction } from "./reconstruction";
import type { SafeSimulation } from "./simulation";
import type { SafetyGuidance } from "./guidance";

export interface CompleteReconstructionResult {
  /** Semantic schema version for contract evolution (e.g. "1.0.0") */
  version: string;
  /** Unique identifier for the completed analysis and reconstruction */
  resultId: string;
  /** ISO-8601 timestamp when the complete result was assembled */
  generatedAt: string;
  /** Dynamic threat findings ingested from upstream AI Threat Analysis */
  threatAnalysis: ThreatAnalysisInput;
  /** Extracted genetic profile and characteristics of the attack */
  attackDNA: AttackDNA;
  /** Reconstructed multi-stage kill chain and attacker objectives */
  attackReconstruction: AttackReconstruction;
  /** Non-executable, educational interactive simulation state machine */
  safeSimulation: SafeSimulation;
  /** Tailored defensive recommendations, immediate actions, and red flags */
  safetyGuidance: SafetyGuidance;
  /** Extensible container for orchestration metadata */
  metadata?: Record<string, unknown>;
}
