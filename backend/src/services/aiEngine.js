/**
 * AI Integration Boundary
 * 
 * Hemanth: This is the dedicated integration point for your AI implementation.
 * The core API pipeline uses this module to fetch intelligence.
 */
class AIEngine {
    /**
     * Executes the AI analysis on the suspicious input.
     * 
     * @param {string} analysisId - The unique request ID for tracing.
     * @param {import('../../../shared/types').InputMetadata} inputMetadata 
     * @returns {Promise<import('../../../shared/types').PhishForensicsResult>}
     */
    static async analyze(analysisId, inputMetadata) {
        // TODO (Hemanth): Implement the external AI API call here (OpenAI, Claude, Gemini, etc.)
        // 1. Construct the prompt dynamically using `inputMetadata.content` and `inputMetadata.type`.
        // 2. Instruct the LLM to output structured JSON matching the PhishForensicsResult contract.
        // 3. Make sure to assign `analysisId` to the `result.analysisId` field in the final object.
        // 4. Parse and validate the response against the shared contract.
        // 5. Return the fully constructed object.
        
        // Per requirements: Do NOT implement fake AI, risk scores, or hardcoded results.
        throw new Error("NOT_IMPLEMENTED_AI_ENGINE_PENDING");
    }
}

module.exports = AIEngine;
