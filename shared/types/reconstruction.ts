/**
 * PhishForensics AI - Attack Reconstruction Contract
 * 
 * Defines the structure for reconstructing the end-to-end attack progression,
 * including objectives, variable stages, supporting evidence, and potential consequences.
 * Supports a variable number of stages without hardcoding a fixed attack sequence.
 */

/**
 * Attacker's overarching objectives derived from the threat analysis.
 */
export interface AttackerObjective {
  /** The core primary objective (e.g. "Harvest corporate SSO credentials via deceptive portal") */
  primaryObjective: string;
  /** Potential secondary or contingency objectives */
  secondaryObjectives?: string[];
  /** Long-term strategic goal if primary objective succeeds */
  strategicGoal?: string;
}

/**
 * Specific evidence anchoring a reconstructed stage to observed data.
 */
export interface StageEvidence {
  /** Reference to an EvidenceItem id or ThreatIndicator from ThreatAnalysisInput */
  evidenceId?: string;
  /** Analytical summary of how this evidence demonstrates this stage */
  summary: string;
  /** Specific observed snippet or indicator value */
  snippet?: string;
  /** Location or component where the evidence exists */
  source?: string;
}

/**
 * Potential real-world consequence if a specific attack stage succeeds.
 */
export interface StageConsequence {
  /** Concise summary of the consequence */
  shortImpact: string;
  /** In-depth explanation of the operational, financial, or security impact */
  detailedConsequence: string;
  /** Qualitative severity level (e.g. "low", "moderate", "severe", "catastrophic") */
  severity?: string;
  /** Specific assets, systems, or accounts that would be compromised */
  affectedAssets?: string[];
}

/**
 * An individual reconstructed stage in the attack progression.
 * The system supports an arbitrary, variable number of stages.
 */
export interface ReconstructionStage {
  /** Unique identifier for the stage within this reconstruction (e.g. "stage-delivery", "stage-harvest") */
  stageId: string;
  /** 1-based sequential position in the reconstructed attack flow */
  sequenceOrder: number;
  /** Descriptive, human-readable title of this stage */
  stageTitle: string;
  /** Detailed narrative explaining what occurs during this phase */
  stageDescription: string;
  /** Optional generic phase category (e.g. "reconnaissance", "delivery", "exploitation", "credential_access", "lateral_movement") */
  phaseCategory?: string;
  /** Grounded evidence items supporting the reconstruction of this stage */
  supportingEvidence: StageEvidence[];
  /** Consequence that would unfold if this stage is reached or succeeds */
  possibleConsequence: StageConsequence;
  /** Keys of AttackDNA traits active in this stage (e.g. ["impersonation", "urgency"]) */
  relevantTraits: string[];
  /** Explanation of the technical or social mechanism used by the attacker */
  mechanism?: string;
  /** Extensible stage metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Complete reconstructed attack narrative and stage sequence.
 */
export interface AttackReconstruction {
  /** Unique identifier for this reconstruction */
  reconstructionId?: string;
  /** Attacker's determined objectives */
  attackerObjective: AttackerObjective;
  /** Variable-length array of reconstructed attack stages */
  stages: ReconstructionStage[];
  /** Total number of reconstructed stages */
  totalStages: number;
  /** High-level narrative summarizing the full attack kill chain from lure to objective */
  attackFlowSummary: string;
  /** Extensible reconstruction metadata */
  metadata?: Record<string, unknown>;
}
