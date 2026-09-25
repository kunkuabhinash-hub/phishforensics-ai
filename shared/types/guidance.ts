/**
 * PhishForensics AI - Safety Guidance Contract
 * 
 * Defines structured defensive recommendations and awareness guidance generated
 * from the threat analysis and attack reconstruction.
 */

/**
 * Immediate tactical defensive action for an individual facing this threat.
 */
export interface DefensiveAction {
  /** Qualitative priority level (e.g. "critical", "high", "medium", "standard") */
  priority: string;
  /** Concrete action statement (e.g. "Forward email to security team and delete from inbox") */
  action: string;
  /** Justification tied directly to the analyzed threat mechanisms */
  reason: string;
}

/**
 * Broader organizational, technical, or policy recommendation to prevent similar attacks.
 */
export interface PreventionRecommendation {
  /** Recommendation category (e.g. "technical_control", "policy", "training", "monitoring") */
  category: string;
  /** Actionable recommendation description */
  recommendation: string;
  /** Rationale connecting back to the attack's DNA and kill chain */
  rationale: string;
  /** Optional reference to industry best practices or security standards */
  reference?: string;
}

/**
 * Specific red flag identified in the attack that users should learn to recognize.
 */
export interface IdentifiedRedFlag {
  /** Summary of the suspicious cue */
  cue: string;
  /** Detailed explanation of why attackers use this tactic and how to recognize it */
  explanation: string;
  /** Where this red flag was observed in the current attack artifact */
  locationFound?: string;
}

/**
 * Top-level safety guidance container combining tactical and preventive advice.
 */
export interface SafetyGuidance {
  /** Unique identifier for this guidance record */
  guidanceId?: string;
  /** Executive guidance summary */
  summary: string;
  /** Immediate steps to take right now if encountering this threat */
  immediateActions: DefensiveAction[];
  /** Long-term technical and behavioral prevention recommendations */
  preventionRecommendations: PreventionRecommendation[];
  /** Concrete red flags identified in this specific attack to train users */
  redFlagsIdentified: IdentifiedRedFlag[];
  /** Recommended awareness training topics based on the attack profile */
  recommendedTrainingTopics?: string[];
  /** Extensible guidance metadata */
  metadata?: Record<string, unknown>;
}
