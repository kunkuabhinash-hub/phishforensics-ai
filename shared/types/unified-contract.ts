import type { ThreatVerdict, ThreatSeverity } from './threat-intelligence.ts';
import type { AttackDNA } from './attack-dna.ts';
import type { AttackReconstruction } from './reconstruction.ts';
import type { SafeSimulation } from './simulation.ts';
import type { SafetyGuidance } from './guidance.ts';
import type { MitreAttackAnalysis } from './mitre.ts';

export interface UnifiedPhishForensicsContract {
  /** Unique tracing identifier for the entire investigation lifecycle */
  analysisId: string;
  /** ISO 8601 UTC timestamp of investigation execution */
  timestamp: string;

  /** The raw input analyzed by the system */
  input: {
    sourceType: string;
    content: string;
  };

  /** AI Threat Intelligence (Sourced from Threat Analysis Pipeline) */
  threatAssessment: {
    verdict: ThreatVerdict;
    severity: ThreatSeverity;
    riskScore: number | null; 
    confidence: number;
    justification: string;
  };
  
  attackerIntent: {
    primaryGoal: string;
    description: string;
    potentialImpact: string | null;
  };

  /** Normalized Evidence (Merging technical indicators, social engineering, and context) */
  evidence: {
    id: string;
    category: 'technical' | 'psychological' | 'contextual';
    value: string; 
    defangedValue: string | null; 
    description: string;
  }[];

  /** Deterministic Orchestration (Sourced from Simulation & Reconstruction Engines) */
  attackDNA?: AttackDNA | null; 
  reconstruction?: AttackReconstruction | null; 
  safeSimulation?: SafeSimulation | null; 
  safetyGuidance?: SafetyGuidance | null; 

  /** Standards-aligned MITRE ATT&CK Enterprise Mapping (Deterministic & Evidence-driven) */
  mitreAttack?: MitreAttackAnalysis | null;
}
