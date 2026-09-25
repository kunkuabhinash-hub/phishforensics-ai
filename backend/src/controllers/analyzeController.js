const AnalyzeService = require('../services/analyzeService');

const analyzeContent = async (req, res) => {
    try {
        const { type, content, source } = req.body;

        // 1. Validation
        if (!type || !content) {
            return res.status(400).json({
                error: 'Bad Request',
                message: 'Missing required fields: type and content are required.'
            });
        }

        const validTypes = ['text', 'url', 'email', 'image', 'other'];
        if (!validTypes.includes(type)) {
            return res.status(400).json({
                error: 'Bad Request',
                message: `Invalid type. Must be one of: ${validTypes.join(', ')}`
            });
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
            return res.status(501).json({
                error: 'Not Implemented',
                message: 'The AI analysis engine is not yet connected to the pipeline.',
                status: 'pending_ai_integration'
            });
        }
        
        console.error('Analyze Controller Error:', error);
        return res.status(500).json({
            error: 'Internal Server Error',
            message: 'An unexpected error occurred during analysis.'
        });
    }
};

module.exports = {
    analyzeContent
};
