const AIEngine = require('./aiEngine');
const { validatePhishForensicsResult } = require('../../../shared/validateContract');

/**
 * Analysis Service
 * Responsible for orchestrating the AI analysis pipeline and future modules.
 */
class AnalyzeService {
    /**
     * Process the suspicious content
     * @param {string} analysisId 
     * @param {import('../../../shared/types').InputMetadata} inputMetadata
     * @returns {Promise<import('../../../shared/types').PhishForensicsResult>}
     */
    static async processContent(analysisId, inputMetadata) {
        try {
            console.log(`[AnalyzeService] Starting analysis for ID: ${analysisId}`);
            
            // 1. Pass the tracing ID and validated input to the AI engine boundary
            const aiResult = await AIEngine.analyze(analysisId, inputMetadata);
            
            // 2. Validate the result returned by the AI engine
            validatePhishForensicsResult(aiResult);
            
            // 3. FUTURE PIPELINE STEPS (Do NOT implement yet)
            
            return aiResult;
            
        } catch (error) {
            console.error(`[AnalyzeService] Error processing content for ID: ${analysisId} - ${error.message}`);
            throw error;
        }
    }
}

module.exports = AnalyzeService;
