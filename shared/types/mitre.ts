/**
 * PhishForensics AI - MITRE ATT&CK Enterprise Mapping Contract
 *
 * Defines standards-aligned MITRE ATT&CK Enterprise tactics and techniques.
 * Used by the deterministic mapping engine to ground forensic findings into formal TTPs.
 */

export interface MitreTactic {
  /** MITRE Tactic ID (e.g., "TA0001") */
  id: string;
  /** MITRE Tactic Name (e.g., "Initial Access") */
  name: string;
  /** Brief description of the tactic */
  description?: string;
  /** Official MITRE ATT&CK reference URL */
  referenceUrl: string;
}

export interface MitreTechniqueMapping {
  /** MITRE Technique ID (e.g., "T1566") */
  techniqueId: string;
  /** MITRE Technique Name (e.g., "Phishing") */
  techniqueName: string;
  /** Specific Sub-technique ID if supported by concrete evidence (e.g., "T1566.001") */
  subTechniqueId?: string | null;
  /** Sub-technique Name (e.g., "Spearphishing Attachment") */
  subTechniqueName?: string | null;
  /** Associated MITRE Tactic */
  tactic: MitreTactic;
  /** Confidence score (0 to 100) reflecting evidence grounding */
  confidence: number;
  /** References to specific evidence IDs, traits, or indicators justifying the mapping */
  supportingEvidenceRefs: string[];
  /** Deterministic rationale explaining why the rule fired based on verified evidence */
  mappingRationale: string;
}

export interface MitreAttackAnalysis {
  /**
   * Mapping quality status:
   * - 'mapped': Sufficient concrete technical evidence grounded specific techniques
   * - 'partial': Broad tactic or parent technique identified, but specific sub-technique lacks concrete artifact proof
   * - 'unmapped': Insufficient or safe evidence to support any MITRE technique
   */
  status: 'mapped' | 'partial' | 'unmapped';
  /** Primary technique representing the main entry/lure vector */
  primaryTechnique: MitreTechniqueMapping | null;
  /** All identified techniques across the attack kill chain */
  techniques: MitreTechniqueMapping[];
  /** Distinct tactics represented across all identified techniques */
  observedTactics: MitreTactic[];
  /** Explicit notes clarifying missing evidence or analytical boundaries */
  uncertaintyNotes: string[];
  /** ISO 8601 UTC timestamp of mapping generation */
  evaluatedAt: string;
}
