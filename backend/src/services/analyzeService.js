const AIEngine = require('./aiEngine');

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
            
            // 2. FUTURE PIPELINE STEPS (Do NOT implement yet):
            // - Attack DNA Extraction (Yashu)
            // - Attack Reconstruction Pipeline (Yashu)
            // - Safe Simulation Setup (Monish)
            
            // 3. Return the fully processed result back to the controller
            return aiResult;
            
        } catch (error) {
            // Propagate errors cleanly to the controller
            console.error('[AnalyzeService] Error processing content:', error.message);
            throw error;
        }
    }
}

module.exports = AnalyzeService;
