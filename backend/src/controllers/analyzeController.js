const AnalyzeService = require('../services/analyzeService');
const AppError = require('../utils/AppError');

const analyzeContent = async (req, res, next) => {
    try {
        const { type, content, source } = req.body;

        // 1. Validation - pass errors to centralized handler via next()
        if (!type || !content) {
            return next(new AppError('Missing required fields: type and content are required.', 400));
        }

        const validTypes = ['text', 'url', 'email', 'image', 'other'];
        if (!validTypes.includes(type)) {
            return next(new AppError(`Invalid type. Must be one of: ${validTypes.join(', ')}`, 400));
        }

        // 2. Construct input metadata adhering to the shared contract
        const inputMetadata = {
            type,
            content,
            source: source || 'unknown',
            timestamp: new Date().toISOString()
        };

        // 3. Hand off to the analysis service
        const result = await AnalyzeService.processContent(inputMetadata);
        
        // 4. Return the PhishForensicsResult (won't be reached until AI is connected)
        return res.status(200).json(result);

    } catch (error) {
        if (error.message === 'NOT_IMPLEMENTED_AI_ENGINE_PENDING') {
            return next(new AppError('The AI analysis engine is not yet connected to the pipeline.', 501));
        }
        
        // Let the centralized error handler deal with unexpected errors
        next(error);
    }
};

module.exports = {
    analyzeContent
};
