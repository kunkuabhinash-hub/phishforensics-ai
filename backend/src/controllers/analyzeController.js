const crypto = require('crypto');
const AnalyzeService = require('../services/analyzeService');
const AppError = require('../utils/AppError');
const { normalizeInput } = require('../utils/inputNormalizer');

const analyzeContent = async (req, res, next) => {
    // Generate a unique identifier for this analysis request
    const analysisId = crypto.randomUUID();

    try {
        const { type, content, source } = req.body;

        // 1. Validation - pass errors to centralized handler via next()
        if (!type || !content) {
            return next(new AppError('Missing required fields: type and content are required.', 400, analysisId));
        }

        const validTypes = ['text', 'url', 'email', 'image', 'other'];
        if (!validTypes.includes(type)) {
            return next(new AppError(`Invalid type. Must be one of: ${validTypes.join(', ')}`, 400, analysisId));
        }

        // 2. Input Normalization
        // Transforms raw validated input into a consistent internal representation for the AI
        const normalizedInput = normalizeInput(analysisId, type, content, source);

        // 3. Hand off to the analysis service
        const result = await AnalyzeService.processContent(analysisId, normalizedInput);
        
        // 4. Return the PhishForensicsResult (won't be reached until AI is connected)
        return res.status(200).json(result);

    } catch (error) {
        if (error.message === 'NOT_IMPLEMENTED_AI_ENGINE_PENDING') {
            return next(new AppError('The AI analysis engine is not yet connected to the pipeline.', 501, analysisId));
        }
        
        // Let the centralized error handler deal with unexpected errors
        error.analysisId = error.analysisId || analysisId;
        next(error);
    }
};

module.exports = {
    analyzeContent
};
