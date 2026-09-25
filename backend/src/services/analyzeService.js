const AIEngine = require('./aiEngine');
const { validatePhishForensicsResult } = require('../../../shared/validateContract');

/**
 * Analysis Service
 * Responsible for orchestrating the AI analysis pipeline and future modules.
 */
class AnalyzeService {
    /**
     * Process the suspicious content
     * @param {import('../../../shared/types').InputMetadata} inputMetadata
     * @returns {Promise<import('../../../shared/types').PhishForensicsResult>}
     */
    static async processContent(inputMetadata) {
        try {
            // 1. Pass the validated input to the AI engine boundary
            const aiResult = await AIEngine.analyze(inputMetadata);
            
            // 2. Validate the result returned by the AI engine
            // If Hemanth's AI returns a malformed response, this will throw an error
            // preventing bad data from reaching the frontend or downstream modules.
            validatePhishForensicsResult(aiResult);
            
            // 3. FUTURE PIPELINE STEPS (Do NOT implement yet):
            // - Attack DNA Extraction (Yashu)
            // - Attack Reconstruction Pipeline (Yashu)
            // - Safe Simulation Setup (Monish)
            
            // 4. Return the fully processed result back to the controller
            return aiResult;
            
        } catch (error) {
            // Propagate errors cleanly to the controller
            console.error('[AnalyzeService] Error processing content:', error.message);
            throw error;
        }
    }
}

module.exports = AnalyzeService;
