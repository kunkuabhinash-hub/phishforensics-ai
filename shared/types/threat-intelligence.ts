/**
 * ============================================================================
 * PHISHFORENSICS AI — CANONICAL THREAT INTELLIGENCE CONTRACT
 * ============================================================================
 *
 * This contract serves as the SINGLE SOURCE OF TRUTH across the entire
 * PhishForensics AI system. All modules (AI Analysis Engine, Backend API,
 * Attack DNA, Attack Reconstruction, Safe Simulation, Education, and Frontend)
 * consume and communicate using this shared contract.
 *
 * DESIGN PRINCIPLES:
 * 1. Evidence-to-Conclusion Traceability: All findings, intents, DNA attributes,
 *    and reconstruction stages reference stable Evidence IDs.
 * 2. Provider Independence: Fully agnostic of specific LLM providers (Gemini, OpenAI, Claude, etc.).
 * 3. Dynamic & Extensible: No hardcoded scores or forced 5-stage attack flows.
 * 4. Explicit Uncertainty: Preserves distinction between Observed, Inferred,
 *    Unverified, and Unknown evidence.
 * 5. Safe & Defensive: Technical indicators are stored alongside defanged values.
 */

// ============================================================================
// 1. INVESTIGATION METADATA
// ============================================================================

export type InvestigationStatus = 'completed' | 'partial' | 'failed' | 'in_progress';

export interface InvestigationMetadata {
  /** Unique investigation identifier (e.g., "INV-20260925-8F92") */
  id: string;
  /** ISO 8601 UTC timestamp of investigation execution */
  timestamp: string;
  /** Version of the canonical threat intelligence schema */
  schemaVersion: string;
  /** Version of the threat analysis engine */
  analyzerVersion: string;
  /** Processing status of the investigation */
  status: InvestigationStatus;
}

// ============================================================================
// 2. SUBMITTED ARTIFACT METADATA (Multi-Artifact Ready)
// ============================================================================

export type ArtifactType =
  | 'email'
  | 'text'
  | 'header'
  | 'url'
  | 'screenshot'
  | 'attachment'
  | 'multi';

export interface SubmittedArtifact {
  /** Unique artifact identifier (e.g., "ART-001") */
  id: string;
  /** Primary artifact category */
  type: ArtifactType;
  /** Original file name or submission label if available */
  name?: string;
  /** File format or extension (e.g., 'eml', 'txt', 'png', 'url') */
  format?: string;
  /** File size in bytes if applicable */
  sizeBytes?: number;
  /** SHA-256 hash of the artifact content for auditability */
  sha256?: string;
  /** Received timestamp in ISO 8601 format */
  receivedAt: string;
  /** Key-value metadata extracted from ingestion */
  metadata?: Record<string, string | number | boolean>;
}

// ============================================================================
// 3. THREAT ASSESSMENT
// ============================================================================

export type ThreatVerdict = 'phishing' | 'suspicious' | 'safe' | 'unknown';
export type ThreatSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown';

export interface ThreatAssessment {
  /** Primary forensic verdict */
  verdict: ThreatVerdict;
  /** Severity level derived from potential impact */
  severity: ThreatSeverity;
  /** Dynamic risk score (0 to 100), or null if evidence is insufficient */
  riskScore: number | null;
  /** Confidence score in the overall verdict (0 to 100) */
  confidenceScore: number;
  /** High-level forensic summary of the assessment */
  summary: string;
  /** Detailed justification explaining how the verdict was derived from evidence */
  verdictJustification: string;
}

// ============================================================================
// 4. EVIDENCE MODEL (Traceability Foundation)
// ============================================================================

export type ObservationStatus = 'observed' | 'inferred' | 'unverified' | 'unknown';

export type EvidenceType =
  | 'header'
  | 'url'
  | 'text_phrase'
  | 'attachment'
  | 'sender'
  | 'metadata'
  | 'visual_element'
  | 'other';

export interface EvidenceItem {
  /** Stable evidence identifier referenced by findings and DNA (e.g., "EV-001") */
  id: string;
  /** Type of evidence extracted */
  type: EvidenceType;
  /** ID of the source artifact from which this evidence was extracted */
  artifactId: string;
  /** Raw content extracted from the submitted artifact */
  rawContent: string;
  /** Defanged, non-executable content (e.g., "http://phish[.]com" or "user[@]domain[.]com") */
  defangedContent?: string;
  /** Location within artifact (e.g., "Email Header: Return-Path", "Body Paragraph 2") */
  location: string;
  /** Direct observation vs inference status */
  status: ObservationStatus;
  /** Human-readable explanation of what this evidence item represents */
  description: string;
  /** Confidence score associated with this specific evidence item (0-100) */
  confidence: number | null;
  /** Additional metadata attributes */
  metadata?: Record<string, string | number | boolean>;
}

// ============================================================================
// 5. GENERIC FINDING MODEL (Extensible Threat Detection)
// ============================================================================

export type FindingStatus = 'observed' | 'inferred' | 'unverified';
export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface FindingItem {
  /** Unique finding identifier (e.g., "FIND-001") */
  id: string;
  /** Extensible category string (e.g., "credential_targeting", "brand_impersonation", "urgency") */
  category: string;
  /** Short title summarizing the finding */
  title: string;
  /** Detailed forensic explanation of the finding */
  description: string;
  /** Evidence IDs directly supporting this finding (Enforces Traceability) */
  supportingEvidenceIds: string[];
  /** Evidence IDs that explicitly contradict or weaken this finding */
  contradictingEvidenceIds?: string[];
  /** Confidence score in this finding (0-100) */
  confidence: number;
  /** Status of observation */
  status: FindingStatus;
  /** Severity rating of this specific finding */
  severity: FindingSeverity;
  /** Impact of this finding on the victim or organization */
  impact: string;
}

// ============================================================================
// 6. ATTACKER INTENT
// ============================================================================

export interface AttackerIntent {
  /** Primary goal inferred from evidence (e.g., "Corporate Credential Harvesting", or "unknown") */
  primaryObjective: string;
  /** Secondary goals if evident (e.g., "MFA Token Theft", "Network Reconnaissance") */
  secondaryObjectives: string[];
  /** Targeted asset or victim resource */
  targetedAsset: string;
  /** Specific action the attacker intended the victim to take */
  intendedVictimAction: string;
  /** Estimated potential consequence if successful */
  potentialImpact: string;
  /** Supporting Evidence IDs */
  supportingEvidenceIds: string[];
  /** Supporting Finding IDs */
  supportingFindingIds: string[];
  /** Confidence in intent assessment (0-100) */
  confidence: number;
  /** Notes regarding intent ambiguity or uncertainty */
  uncertaintyNotes: string | null;
}

// ============================================================================
// 7. VICTIM REQUESTED ACTION
// ============================================================================

export interface VictimRequestedAction {
  /** Category of requested action (e.g., "click_link", "download_attachment", "wire_funds") */
  actionType: string;
  /** Full description of the action requested by the artifact */
  description: string;
  /** Urgency level conveyed to the victim */
  urgencyLevel: 'high' | 'medium' | 'low' | 'none' | 'unknown';
  /** Target channel used (e.g., "fake_login_portal", "phone_call", "reply_email") */
  targetChannel: string;
  /** Evidence IDs demonstrating this request */
  supportingEvidenceIds: string[];
  /** Confidence score (0-100) */
  confidence: number;
}

// ============================================================================
// 8. SOCIAL ENGINEERING & MANIPULATION TECHNIQUES
// ============================================================================

export interface SocialEngineeringTechnique {
  /** Unique technique identifier (e.g., "SE-001") */
  id: string;
  /** Descriptive technique name (e.g., "False Urgency", "Brand Impersonation", "Authority Abuse") */
  techniqueName: string;
  /** Explanation of how the technique is employed in the artifact */
  explanation: string;
  /** Evidence IDs proving or suggesting this manipulation */
  supportingEvidenceIds: string[];
  /** Confidence score (0-100) */
  confidence: number;
  /** Status of observation */
  status: 'observed' | 'inferred';
}

// ============================================================================
// 9. TECHNICAL INDICATORS (De-fanged & Safe)
// ============================================================================

export type TechnicalIndicatorType =
  | 'url'
  | 'domain'
  | 'sender'
  | 'email_address'
  | 'phone_number'
  | 'attachment'
  | 'ip'
  | 'header'
  | 'impersonated_entity'
  | 'other';

export interface TechnicalIndicator {
  /** Unique indicator identifier (e.g., "IOC-001") */
  id: string;
  /** Category of technical indicator */
  type: TechnicalIndicatorType;
  /** Exact extracted value */
  value: string;
  /** Safe, non-executable representation (e.g., "hxxps://bad-domain[.]com") */
  defangedValue: string;
  /** Context in which indicator appeared */
  context: string;
  /** Supporting Evidence IDs */
  supportingEvidenceIds: string[];
  /** Risk rating of this specific indicator */
  suspicionLevel: 'critical' | 'high' | 'medium' | 'low' | 'neutral' | 'unknown';
  /** Extensible indicator metadata */
  metadata?: Record<string, string | number | boolean>;
}

// ============================================================================
// 10. ATTACK DNA SOURCE DATA (Consumer: Attack DNA Module)
// ============================================================================

export interface AttackDNAAttribute {
  /** Unique attribute ID (e.g., "DNA-ATTR-001") */
  id: string;
  /** Attribute grouping (e.g., "Psychological Trigger", "Delivery Technique", "Targeting Depth") */
  category: string;
  /** Specific characteristic name (e.g., "Urgency Exploitation", "Spoofed Identity Precision") */
  characteristic: string;
  /** Extracted or derived value (e.g., "High Urgency / Account Termination Threat") */
  value: string;
  /** Evidence IDs supporting this DNA attribute */
  supportingEvidenceIds: string[];
  /** Status of this behavioral attribute observation */
  status: 'observed' | 'inferred' | 'unverified' | 'unknown';
  /** Confidence in attribute extraction (0-100) */
  confidence: number;
  /** Explanation of how this behavioral signature was identified */
  explanation: string;
  /** Extensible property store for downstream Attack DNA visualization engines */
  metadata?: Record<string, string | number | boolean>;
}

export interface AttackDNASource {
  /** Array of extensible behavioral DNA attributes */
  attributes: AttackDNAAttribute[];
}

// ============================================================================
// 11. ATTACK RECONSTRUCTION STAGES (Consumer: Attack Reconstruction Module)
// ============================================================================

export interface ReconstructionStage {
  /** Unique stage identifier (e.g., "STAGE-1") */
  stageId: string;
  /** Sequential order in the attack progression (1-indexed) */
  order: number;
  /** Dynamic stage title (e.g., "Initial Contact & Lure", "Credential Capture Prompt") */
  stageName: string;
  /** Detailed description of what occurs during this attack step */
  description: string;
  /** Supporting Evidence IDs */
  supportingEvidenceIds: string[];
  /** Supporting Finding IDs */
  supportingFindingIds: string[];
  /** Confidence in this stage reconstruction (0-100) */
  confidence: number;
  /** Status of observation */
  status: 'observed' | 'inferred' | 'unverified' | 'unknown';
  /** The specific victim action requested or required during this stage, if applicable */
  victimAction?: string;
  /** Safe, defensive hypothetical consequence if the victim action or stage succeeded */
  safeConsequence?: string;
  /** What remains unknown or unverified about this stage */
  uncertaintyNotes?: string;
  /** ID of preceding stage if linked */
  previousStageId?: string | null;
  /** ID of succeeding stage if linked */
  nextStageId?: string | null;
}

// ============================================================================
// 12. UNCERTAINTY & MISSING EVIDENCE
// ============================================================================

export interface UnverifiedClaim {
  /** Specific assertion or statement made in analysis */
  claim: string;
  /** Reason why it cannot be verified with provided evidence */
  reasonUnverified: string;
  /** Evidence IDs related to the unverified claim */
  evidenceIds: string[];
}

export interface ConflictingSignal {
  /** First observed or inferred signal */
  signalA: string;
  /** Second conflicting signal */
  signalB: string;
  /** Forensic explanation of the contradiction */
  explanation: string;
}

export interface UncertaintyReport {
  /** Overall narrative explaining analytical limitations and uncertainties */
  overallUncertaintyNotes: string;
  /** Claims derived from analysis that lack definitive evidence */
  unverifiedClaims: UnverifiedClaim[];
  /** Contradictory evidence signals detected */
  conflictingSignals: ConflictingSignal[];
}

export interface MissingEvidenceItem {
  /** Unique missing evidence identifier (e.g., "MISSING-001") */
  id: string;
  /** Description of what evidence is absent (e.g., "Full Email RFC 822 Headers") */
  missingItem: string;
  /** Explanation of why this evidence would be valuable */
  whyNeeded: string;
  /** Analytical impact of not having this evidence */
  impactOnAnalysis: string;
}

// ============================================================================
// 13. DEFENSIVE RECOMMENDATIONS (Consumer: Defense & Awareness Module)
// ============================================================================

export type RecommendationPriority = 'critical' | 'high' | 'medium' | 'low';

export interface DefensiveRecommendation {
  /** Unique recommendation ID (e.g., "REC-001") */
  id: string;
  /** Priority level for immediate action */
  priority: RecommendationPriority;
  /** Concise recommendation title */
  title: string;
  /** Actionable defensive step for the user/administrator */
  action: string;
  /** Explanation of why this recommendation mitigates the threat */
  rationale: string;
  /** Associated Finding IDs */
  supportingFindingIds: string[];
  /** Associated Evidence IDs */
  supportingEvidenceIds: string[];
  /** Recommended safe alternative next step */
  safeNextStep: string;
}

// ============================================================================
// 14. EDUCATIONAL EXPLANATION (Consumer: Education / "Why This Works")
// ============================================================================

export interface EducationalExplanation {
  /** Plain-language narrative of what transpired in the attack artifact */
  whatHappened: string;
  /** What the artifact explicitly shows (Observed facts) */
  knownFacts: string[];
  /** What the evidence suggests (Inferred possibilities) */
  inferredAssumptions: string[];
  /** What cannot be established from the evidence (Unknowns) */
  unknownFactors: string[];
  /** Psychological and tactical explanation of why this attack technique succeeds */
  whyThisWorks: string;
  /** Highlighted red flags for user awareness */
  keySignalsNoticed: string[];
  /** Core psychological exploitation vector (e.g., "Urgency + Fear of Account Suspension") */
  psychologicalMechanism: string;
  /** Training advice on how to respond safely in similar scenarios */
  saferAlternativeBehavior: string;
}

// ============================================================================
// 15. ANALYSIS LIMITATIONS
// ============================================================================

export interface AnalysisLimitations {
  /** Explicit list of analytical boundaries */
  limitations: string[];
  /** Key assumptions made during investigation */
  assumptionsMade: string[];
}

// ============================================================================
// 16. INVESTIGATION TIMELINE (Consumer: Timeline UI)
// ============================================================================

export type TimelineEventType =
  | 'observed_artifact'
  | 'detected_tactic'
  | 'inferred_intent'
  | 'victim_action'
  | 'attacker_goal'
  | 'defensive_checkpoint';

export interface TimelineEvent {
  /** Unique event identifier (e.g., "EVT-001") */
  id: string;
  /** ISO timestamp if available from evidence or metadata */
  timestamp?: string;
  /** Provenance of the timestamp (e.g., "Email Header", "Attachment Metadata", "Submission Metadata") */
  timestampProvenance?: string;
  /** Event headline */
  title: string;
  /** Event detailed narrative */
  description: string;
  /** Type of timeline event */
  eventType: TimelineEventType;
  /** Supporting Evidence IDs */
  supportingEvidenceIds: string[];
  /** Artifact IDs from which this event was derived */
  artifactIds: string[];
  /** Confidence in timeline placement (0-100) */
  confidence: number;
  /** Status of event observation */
  status: 'observed' | 'inferred' | 'unverified' | 'unknown';
}

export interface AttackNarrative {
  initialSignal: string;
  socialEngineeringMechanism: string;
  requestedVictimAction: string;
  technicalCharacteristics: string;
  defensiveReconstruction: string;
  unknownFactors: string[];
}

// ============================================================================
// 17. CROSS-ARTIFACT CORRELATION
// ============================================================================

export type CrossArtifactRelationshipType =
  | 'shared_sender'
  | 'shared_domain'
  | 'shared_url'
  | 'shared_header_indicator'
  | 'shared_text_indicator'
  | 'temporal_relationship'
  | 'supporting_context'
  | 'contradicting_context'
  | 'unknown_relationship';

export interface CrossArtifactCorrelation {
  /** Unique correlation ID (e.g., CORR-001) */
  id: string;
  /** The artifact IDs involved in this correlation */
  artifactIds: string[];
  /** The specific evidence IDs that establish this correlation */
  supportingEvidenceIds: string[];
  /** Type of relationship */
  relationshipType: CrossArtifactRelationshipType;
  /** Detailed explanation of the correlation */
  explanation: string;
  /** Status / Confidence state */
  status: 'observed' | 'inferred' | 'unverified' | 'unknown';
}

// ============================================================================
// 18. CANONICAL THREAT INTELLIGENCE (The Root Contract)
// ============================================================================

export interface CanonicalThreatIntelligence {
  /** Metadata regarding this investigation session */
  investigation: InvestigationMetadata;
  /** List of submitted artifacts analyzed (Multi-artifact support) */
  artifacts: SubmittedArtifact[];
  /** Overall forensic threat assessment & verdict */
  threatAssessment: ThreatAssessment;
  /** Granular evidence ledger (Traceability anchor) */
  evidence: EvidenceItem[];
  /** Generic forensic findings */
  findings: FindingItem[];
  /** Assessed attacker intent and objectives */
  attackerIntent: AttackerIntent;
  /** Requested victim action details */
  victimRequestedAction: VictimRequestedAction;
  /** Social engineering and manipulation techniques */
  socialEngineering: SocialEngineeringTechnique[];
  /** De-fanged technical indicators (IOCs) */
  technicalIndicators: TechnicalIndicator[];
  /** Behavior attributes for the Attack DNA consumer module */
  attackDNASource: AttackDNASource;
  /** Reconstruction stages for the Attack Reconstruction consumer module */
  reconstructionTimeline: ReconstructionStage[];
  /** Explicit uncertainty report preserving unknown/unverified details */
  uncertaintyReport: UncertaintyReport;
  /** Breakdown of missing evidence items */
  missingEvidence: MissingEvidenceItem[];
  /** Tailored defensive recommendations */
  defensiveRecommendations: DefensiveRecommendation[];
  /** Educational explanation for awareness and "Why This Works" UI */
  educationalExplanation: EducationalExplanation;
  /** Explicit analysis boundaries and assumptions */
  analysisLimitations: AnalysisLimitations;
  /** Timeline events for visual investigation timeline UI */
  investigationTimeline: TimelineEvent[];
  /** Structured, readable narrative answering What and How */
  attackNarrative: AttackNarrative;
  /** Assessment of investigation completeness and gaps */
  investigationQuality: InvestigationQuality;
  /** Explicit cross-artifact relationships and correlations */
  crossArtifactCorrelations: CrossArtifactCorrelation[];
  /** Deterministic relationship graph connecting evidence to conclusions */
  evidenceGraph: EvidenceGraph;
}

// ============================================================================
// 19. INVESTIGATION QUALITY & ANALYST DECISION SUPPORT
// ============================================================================

export type InvestigationCompletenessStatus = 'strong' | 'partial' | 'weak' | 'unknown';

export interface NextInvestigationAction {
  /** The action the analyst should perform */
  action: string;
  /** The reason this action is needed (derived from missing evidence) */
  reason: string;
}

export interface InvestigationQuality {
  /** Qualitative description of how well the provided artifacts cover the necessary evidence space */
  evidenceCoverage: string;
  /** Qualitative description of how well the analytical findings are supported by the evidence */
  findingSupportCoverage: string;
  /** Explicit unanswered questions resulting from missing evidence or conflicts */
  unresolvedQuestions: string[];
  /** Defensive analyst actions recommended to close investigation gaps */
  nextInvestigationActions: NextInvestigationAction[];
  /** High-level warnings regarding interpretation (e.g. "Low evidence support", "Conflicting signals") */
  analystWarnings: string[];
  /** Overall completeness of the investigation based on available data */
  completenessStatus: InvestigationCompletenessStatus;
}

// ============================================================================
// 18. EVIDENCE GRAPH (Consumer: Future Graph UI / Explainability Layer)
// ============================================================================

export type GraphNodeType =
  | 'artifact'
  | 'evidence'
  | 'finding'
  | 'attack_dna'
  | 'victim_action'
  | 'reconstruction_stage'
  | 'recommendation';

export interface GraphNode {
  /** Matches an existing ID in the canonical intelligence (e.g., "EV-001") */
  id: string;
  /** Type of the canonical entity */
  type: GraphNodeType;
  /** Human-readable short label (e.g., "Suspicious Sender Domain") */
  label: string;
  /** Observation status if applicable */
  status?: 'observed' | 'inferred' | 'unverified' | 'unknown';
}

export type GraphRelationshipType =
  | 'artifact_contains_evidence'
  | 'evidence_supports_finding'
  | 'evidence_contradicts_finding'
  | 'evidence_supports_attack_dna'
  | 'finding_supports_reconstruction'
  | 'finding_supports_recommendation'
  | 'evidence_supports_recommendation';

export interface GraphRelationship {
  /** Unique relationship ID (e.g., "REL-001") */
  id: string;
  /** Source node ID */
  fromNodeId: string;
  /** Target node ID */
  toNodeId: string;
  /** Type of semantic relationship */
  relationshipType: GraphRelationshipType;
}

export interface EvidenceGraph {
  nodes: GraphNode[];
  relationships: GraphRelationship[];
}

// ============================================================================
// 19. ANALYST INVESTIGATION VIEW (Consumer: Frontend Dashboard)
// ============================================================================

export interface AnalystInvestigationSummary {
  investigationId: string;
  verdict: ThreatVerdict | null;
  severity: ThreatSeverity | null;
  riskScore: number | null;
  completenessStatus: InvestigationCompletenessStatus;
  artifactCount: number;
  evidenceCount: number;
  findingCount: number;
  unresolvedQuestionCount: number;
  missingEvidenceCount: number;
  correlationCount: number;
}

export interface AnalystFindingView {
  findingId: string;
  title: string;
  description: string;
  status: 'observed' | 'inferred' | 'unverified' | 'unknown';
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: number | null;
  supportingEvidenceIds: string[];
  contradictingEvidenceIds: string[];
}

export interface AnalystAttackDNAView {
  attributeId: string;
  category: string;
  characteristic: string;
  description: string;
  status: 'observed' | 'inferred' | 'unverified' | 'unknown';
  supportingEvidenceIds: string[];
}

export interface AnalystReconstructionStageView {
  stageId: string;
  stageName: string;
  description: string;
  status: 'observed' | 'inferred' | 'unverified' | 'unknown';
  victimAction?: string;
  safeConsequence?: string;
  uncertaintyNotes?: string;
  supportingEvidenceIds: string[];
}

export interface AnalystCorrelationView {
  correlationId: string;
  artifactIds: string[];
  relationshipType: string;
  explanation: string;
  status: 'observed' | 'inferred' | 'unverified' | 'unknown';
  supportingEvidenceIds: string[];
}

export interface AnalystTimelineEventView {
  eventId: string;
  timestamp: string | undefined;
  timestampProvenance: string;
  eventDescription: string;
  status: 'observed' | 'inferred' | 'unknown';
  artifactIds: string[];
}

export type ExplanationState = 
  | 'supported'
  | 'partially_supported'
  | 'conflicted'
  | 'insufficient_evidence'
  | 'unknown';

export interface ExplanationEvidenceReference {
  evidenceId: string;
  artifactId: string;
  evidenceType: string;
  status: 'observed' | 'inferred' | 'unverified' | 'unknown';
  safeRepresentation: string;
  originalDescription: string;
  timestamp: string | undefined;
}

export interface FindingExplanation {
  findingId: string;
  conclusionSummary: string;
  status: 'observed' | 'inferred' | 'unverified' | 'unknown';
  explanationState: ExplanationState;
  supportingEvidence: ExplanationEvidenceReference[];
  contradictingEvidence: ExplanationEvidenceReference[];
  missingEvidenceReferences: string[];
  artifactIds: string[];
}

export interface AnalystInvestigationView {
  summary: AnalystInvestigationSummary;
  evidenceOverview: EvidenceItem[];
  keyFindings: AnalystFindingView[];
  findingExplanations: FindingExplanation[];
  uncertaintyAndUnknowns: UncertaintyReport;
  attackerIntent: AttackerIntent;
  victimRequestedAction: VictimRequestedAction;
  socialEngineering: SocialEngineeringTechnique[];
  technicalIndicators: TechnicalIndicator[];
  attackDNA: AnalystAttackDNAView[];
  crossArtifactCorrelations: AnalystCorrelationView[];
  investigationTimeline: AnalystTimelineEventView[];
  attackNarrative: AttackNarrative;
  reconstruction: AnalystReconstructionStageView[];
  investigationQuality: InvestigationQuality;
  missingEvidence: MissingEvidenceItem[];
  defensiveRecommendations: DefensiveRecommendation[];
  traceabilityAudit: InvestigationTraceabilityAudit;
}

// ============================================================================
// 20. INVESTIGATION TRACEABILITY AUDIT
// ============================================================================

export type TraceabilityState = 
  | 'fully_traceable'
  | 'partially_traceable'
  | 'conflicted'
  | 'untraceable'
  | 'unknown';

export interface FindingTraceabilityRecord {
  findingId: string;
  status: 'observed' | 'inferred' | 'unverified' | 'unknown';
  supportingEvidenceIds: string[];
  contradictingEvidenceIds: string[];
  missingEvidenceIds: string[];
  supportingEvidenceResolved: number;
  contradictingEvidenceResolved: number;
  traceabilityState: TraceabilityState;
}

export interface EvidenceTraceabilityRecord {
  evidenceId: string;
  artifactId: string;
  usedByFindingIds: string[];
  usedAsSupportingEvidence: boolean;
  usedAsContradictingEvidence: boolean;
  usageState: 'used' | 'unused' | 'unknown';
}

export type ArtifactCoverageState = 
  | 'covered'
  | 'partially_covered'
  | 'no_evidence'
  | 'unknown';

export interface ArtifactTraceabilityRecord {
  artifactId: string;
  evidenceIds: string[];
  findingIds: string[];
  coverageState: ArtifactCoverageState;
}

export interface InvestigationTraceabilityAuditSummary {
  totalFindings: number;
  findingsWithSupportingEvidence: number;
  findingsWithContradictingEvidence: number;
  findingsWithMissingEvidence: number;
  totalEvidenceItems: number;
  evidenceUsedByFindings: number;
  unusedEvidenceItems: number;
  totalArtifacts: number;
  artifactsWithEvidence: number;
  artifactsWithoutEvidence: number;
}

export interface InvestigationTraceabilityAudit {
  summary: InvestigationTraceabilityAuditSummary;
  findingAudits: FindingTraceabilityRecord[];
  evidenceAudits: EvidenceTraceabilityRecord[];
  artifactAudits: ArtifactTraceabilityRecord[];
  unresolvedTraceabilityIssues: string[];
}

// ============================================================================
// 21. CROSS-INVESTIGATION BEHAVIORAL PATTERN COMPARISON
// ============================================================================

export type BehavioralPatternType = 
  | 'attack_dna'
  | 'social_engineering_technique'
  | 'victim_requested_action'
  | 'shared_observable';

export type PatternComparisonStatus = 
  | 'shared'
  | 'unique'
  | 'conflicted'
  | 'unknown';

export interface BehavioralPatternMatch {
  patternId: string;
  patternType: BehavioralPatternType;
  label: string;
  investigationIds: string[];
  supportingEvidenceByInvestigation: Record<string, string[]>;
  statusByInvestigation: Record<string, 'observed' | 'inferred' | 'unverified' | 'unknown'>;
  status: PatternComparisonStatus;
  explanation: string;
}

export interface CrossInvestigationPatternComparisonSummary {
  totalInvestigationsCompared: number;
  sharedPatternCount: number;
  uniquePatternCount: number;
  conflictedPatternCount: number;
  unknownPatternCount: number;
}

export interface CrossInvestigationPatternComparison {
  investigationIds: string[];
  sharedPatterns: BehavioralPatternMatch[];
  uniquePatternsByInvestigation: Record<string, BehavioralPatternMatch[]>;
  contradictoryPatterns: BehavioralPatternMatch[];
  unknownPatterns: BehavioralPatternMatch[];
  summary: CrossInvestigationPatternComparisonSummary;
}
