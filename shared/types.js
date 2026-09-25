/**
 * @file types.js
 * @description Shared Data Contract for PhishForensics AI
 * 
 * This file defines the common data structures used across the entire application pipeline:
 * User Input -> Backend API -> AI Analysis -> Threat Result -> Attack DNA -> 
 * Attack Reconstruction -> Safe Simulation -> Education -> Frontend.
 * 
 * Teammates: Use these JSDoc type definitions to structure your inputs and outputs.
 * - Backend/API: Use these to validate and define the API response structure.
 * - AI Analysis: Return data conforming to this structure after processing the user's input.
 * - Attack DNA & Reconstruction: Consume the threat intent and indicators to build the attack chain.
 * - Safe Simulation: Use the reconstruction data to generate visual/safe consequence simulations.
 * - Frontend: Use these types to safely render UI components without breaking changes.
 */

/**
 * @typedef {'text' | 'url' | 'email' | 'image' | 'other'} InputType
 */

/**
 * Represents the original user input that is being analyzed.
 * Extensible to support multiple formats (text, URLs, images, raw emails, etc.).
 * @typedef {Object} InputMetadata
 * @property {InputType} type - The format of the input (e.g., text, url, image, email).
 * @property {string} content - The raw content, URL, or identifier for the uploaded file.
 * @property {string} [source] - Optional context about where this was found (e.g., "SMS", "WhatsApp", "Email").
 * @property {string} timestamp - ISO timestamp of when the analysis was requested.
 */

/**
 * Represents the overall system verdict and risk score.
 * @typedef {Object} RiskAssessment
 * @property {number} score - A normalized risk score from 0 to 100 (100 being most dangerous).
 * @property {'safe' | 'suspicious' | 'malicious'} severity - Human-readable severity level.
 * @property {number} confidence - The AI's confidence level in this assessment (0.0 to 1.0).
 */

/**
 * Detailed evidence and indicators of compromise or manipulation.
 * Clearly separates psychological manipulation from technical red flags.
 * @typedef {Object} EvidenceIndicators
 * @property {Array<{technique: string, description: string, severity: string}>} psychological - Manipulation tactics (e.g., urgency, authority, fear).
 * @property {Array<{type: string, value: string, description: string}>} technical - Technical red flags (e.g., mismatched domains, hidden links, spoofed headers).
 */

/**
 * Represents the attacker's fingerprint or methodology.
 * @typedef {Object} AttackDNA
 * @property {string} suspectedActor - Profile of the likely attacker (e.g., "Financial Scammer", "State-sponsored").
 * @property {Array<string>} tactics - High-level MITRE ATT&CK style tactics observed.
 * @property {string} signature - A unique fingerprint hash or identifier based on the attack characteristics.
 */

/**
 * Represents a single stage in the reconstructed attack flow.
 * @typedef {Object} AttackStage
 * @property {number} step - The sequence number in the attack chain.
 * @property {string} name - Name of the stage (e.g., "Delivery", "Reconnaissance", "Exploitation").
 * @property {string} description - Narrative description of what happens during this stage.
 */

/**
 * Represents the simulated outcome if the user fell for the attack.
 * @typedef {Object} SafeSimulation
 * @property {Array<string>} potentialConsequences - List of negative outcomes (e.g., "Credential Theft", "Ransomware Installation").
 * @property {string} simulatedOutcomeDescription - Narrative explanation of the potential impact.
 */

/**
 * Educational content tailored to the specific attack to help the user.
 * @typedef {Object} EducationalInsights
 * @property {Array<string>} recommendedActions - Immediate steps the user should take (e.g., "Do not click the link", "Report to IT").
 * @property {Array<string>} keyLearnings - Takeaways to help the user identify similar attacks in the future.
 */

/**
 * The unified shared contract representing the complete result of a PhishForensics investigation.
 * This is the primary object passed down the pipeline and returned to the frontend.
 * 
 * DO NOT hardcode values into this structure. This must be generated dynamically 
 * based on the user's input.
 * 
 * @typedef {Object} PhishForensicsResult
 * @property {string} analysisId - Unique identifier for the investigation.
 * @property {InputMetadata} input - The original input provided by the user.
 * @property {RiskAssessment} risk - Overall risk evaluation.
 * @property {string} threatIntent - The primary goal of the attacker (e.g., "Credential Harvesting", "Financial Fraud").
 * @property {EvidenceIndicators} indicators - Extracted psychological and technical evidence.
 * @property {AttackDNA} dna - The attacker's fingerprint and methodology.
 * @property {Array<AttackStage>} reconstruction - Step-by-step breakdown of how the attack works.
 * @property {SafeSimulation} simulation - The potential consequences of the attack.
 * @property {EducationalInsights} education - Recommendations and learning points for the user.
 */

module.exports = {
  // Types are exported via JSDoc comments for cross-module type checking.
};
