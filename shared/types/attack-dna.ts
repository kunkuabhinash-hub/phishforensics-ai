/**
 * PhishForensics AI - Attack DNA Contract
 * 
 * Defines the structured representation of an attack's core genetic traits and characteristics.
 * Supports dynamically generated traits (impersonation, urgency, fear, authority, etc.)
 * without hardcoding fixed production scores or values.
 */

/**
 * An individual genetic trait or characteristic of the analyzed attack.
 */
export interface AttackTrait {
  /** Machine-readable trait identifier (e.g. "impersonation", "urgency", "fear", "authority", "credential_targeting") */
  key: string;
  /** Human-readable display label (e.g. "Brand Impersonation", "Time-Pressure Urgency") */
  label: string;
  /** Whether this trait is actively present in the analyzed attack */
  present: boolean;
  /** Qualitative intensity (e.g. "subtle", "moderate", "pronounced", "dominant") - non-hardcoded */
  intensity?: string;
  /** In-depth description of how this trait manifests in this particular attack */
  description: string;
  /** References to indicator values or evidence items demonstrating this trait */
  supportingEvidenceRefs: string[];
  /** Extensible trait-specific metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Standard characteristic traits dynamically populated by analysis,
 * with support for arbitrary open-ended custom traits.
 */
export interface CategorizedTraits {
  /** Deceptive mimicry of trusted brands, organizations, or individuals */
  impersonation?: AttackTrait;
  /** Artificial time limits and rapid action inducements */
  urgency?: AttackTrait;
  /** Intimidation, negative consequence threats, or account penalties */
  fear?: AttackTrait;
  /** Coercive use of leadership, legal, or administrative standing */
  authority?: AttackTrait;
  /** Specific focus on obtaining authentication secrets, tokens, or credentials */
  credentialTargeting?: AttackTrait;
  /** Direct financial transfer, invoice fraud, or payment diversion */
  financialTargeting?: AttackTrait;
  /** Psychological manipulation, trust exploitation, or curiosity lures */
  socialEngineering?: AttackTrait;
  /** Extensible index for any additional AI-identified traits */
  [customKey: string]: AttackTrait | undefined;
}

/**
 * Full genetic profile representing the characteristics of the analyzed attack.
 */
export interface AttackDNA {
  /** Unique identifier for this DNA profile */
  dnaId?: string;
  /** High-level executive synthesis of the attack's genetic profile */
  profileSummary: string;
  /** Flat list of all evaluated traits for iterative rendering and filtering */
  traits: AttackTrait[];
  /** Structured mapping for direct programmatic access to key traits */
  categorizedTraits: CategorizedTraits;
  /** Qualitative complexity evaluation (e.g. "commodity", "targeted", "advanced spear-phish") */
  complexity: string;
  /** Primary entry vector (e.g. "email_phish", "credential_harvesting_page", "qr_code_lure", "sms_smish") */
  deliveryVector: string;
  /** Contextual description of the profile being targeted */
  targetProfile?: string;
  /** Open metadata container */
  metadata?: Record<string, unknown>;
}
