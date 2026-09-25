/**
 * PhishForensics AI - Safe Simulation Contract
 * 
 * Defines the contract for an educational, completely non-executable simulation state machine.
 * Models decision paths, consequences, and guidance for interactive learning.
 * Represents what COULD happen without ever executing real attacks or real exploits.
 */

/**
 * Visual or situational environment context simulated in a safe sandbox.
 */
export interface SimulatedEnvironment {
  /** Safe representation of the context (e.g. "email_client", "web_browser", "login_page", "mfa_prompt") */
  contextType: string;
  /** Educational title of the environment view */
  viewTitle?: string;
  /** Completely benign, sanitized display elements for visual rendering (NO live links or executable code) */
  safeDisplayElements?: Record<string, string>;
}

/**
 * Safe, educational consequence resulting from a user choice in the simulation.
 */
export interface SafeConsequence {
  /** Qualitative nature of the outcome (e.g. "safe_defense", "credential_exposure", "malware_risk", "neutral") */
  outcomeType: string;
  /** Educational breakdown explaining what WOULD happen in real life and why */
  explanation: string;
  /** Explicit educational flag clarifying if this choice in a real scenario would lead to compromise */
  wouldLeadToCompromise: boolean;
  /** Indicators or clues that would be revealed if this path were taken */
  revealedIndicators?: string[];
}

/**
 * Targeted learning guidance displayed at a decision point or outcome.
 */
export interface EducationalGuidance {
  /** Catchy, memorable defensive principle */
  headline: string;
  /** Clear educational lesson */
  keyTakeaway: string;
  /** Practical step the user can take in their daily routine to verify or stay safe */
  practicalTip?: string;
}

/**
 * An action or choice presented to the user within a simulation state.
 */
export interface SimulationChoice {
  /** Unique identifier for the choice within the simulation */
  choiceId: string;
  /** User-facing label or action description (e.g. "Click the link to verify credentials", "Inspect sender header") */
  label: string;
  /** Explanatory description of what this action entails */
  actionDescription?: string;
  /** Whether this action represents the defensive best practice */
  isRecommendedAction: boolean;
  /** Safe consequence that unfolds if this choice is selected */
  safeConsequence: SafeConsequence;
  /** State ID of the next SimulationState to transition to */
  nextStateId: string;
}

/**
 * An individual state within the safe simulation state machine.
 */
export interface SimulationState {
  /** Unique state identifier (e.g. "initial_lure", "inspect_url", "credential_portal", "attack_neutralized") */
  stateId: string;
  /** Title of the current scenario step */
  title: string;
  /** Narrative description of the current situation */
  narrative: string;
  /** Whether this state represents a final outcome of the scenario */
  isTerminal: boolean;
  /** Simulated, safe non-executable environment context */
  simulatedEnvironment?: SimulatedEnvironment;
  /** Available choices for the user to make at this decision point */
  availableChoices: SimulationChoice[];
  /** Educational takeaway embedded in this state */
  educationalGuidance?: EducationalGuidance;
  /** Extensible state metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Top-level contract for the safe interactive simulation scenario.
 */
export interface SafeSimulation {
  /** Unique identifier for this simulation instance */
  simulationId?: string;
  /** Title of the educational simulation scenario */
  title: string;
  /** Contextual briefing introducing the scenario to the user */
  scenarioOverview: string;
  /** The starting stateId of the simulation */
  initialStateId: string;
  /** Map of all simulation states indexed by stateId for constant-time state transition lookup */
  states: Record<string, SimulationState>;
  /** Explicit safety disclaimer confirming this is a sandbox for awareness only */
  safetyDisclaimer: string;
  /** Total number of decision states in the simulation */
  totalDecisionPoints: number;
  /** Extensible simulation metadata */
  metadata?: Record<string, unknown>;
}
