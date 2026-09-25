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
     * @param {import('../../../shared/types').InputMetadata} normalizedInput 
     * @returns {Promise<import('../../../shared/types').PhishForensicsResult>}
     */
    static async analyze(analysisId, normalizedInput) {
        // Safely load AI configuration from environment variables
        const provider = process.env.AI_PROVIDER;
        const model = process.env.AI_MODEL;
        const apiKey = process.env.AI_API_KEY;

        if (!apiKey) {
            console.warn(`[AIEngine] Warning: AI_API_KEY is not configured. Analysis ID: ${analysisId}`);
        }

        /* 
         * ====================================================================
         * HEMANTH - AI INTEGRATION INSTRUCTIONS
         * ====================================================================
         * 1. Call your chosen LLM (OpenAI/Claude/Gemini) using the config above.
         * 2. Feed `normalizedInput.content` and `normalizedInput.formatInfo` to the model.
         * 3. Instruct the model to return JSON matching the `PhishForensicsResult` contract in shared/types.js.
         * 4. Parse the LLM response.
         * 5. Ensure you inject the trace identifiers back into the response before returning:
         * 
         *    return {
         *       analysisId: analysisId,             // CRITICAL: Preserve the tracing ID
         *       input: normalizedInput,             // CRITICAL: Preserve original input
         *       risk: parsedLlmData.risk,
         *       threatIntent: parsedLlmData.threatIntent,
         *       indicators: parsedLlmData.indicators,
         *       dna: parsedLlmData.dna,
         *       reconstruction: parsedLlmData.reconstruction,
         *       simulation: parsedLlmData.simulation,
         *       education: parsedLlmData.education
         *    };
         * 
         * NOTE: The returned object will be automatically validated against 
         * `shared/validateContract.js` by the AnalyzeService.
         * ====================================================================
         */
        
        // Per requirements: Do NOT implement fake AI, risk scores, or hardcoded results.
        throw new Error("NOT_IMPLEMENTED_AI_ENGINE_PENDING");
    }
}

module.exports = AIEngine;
