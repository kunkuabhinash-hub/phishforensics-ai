const AppError = require('../utils/AppError');

/**
 * Centralized Error Handling Middleware
 * Ensures consistent JSON error responses and prevents leaking internal details.
 */
const errorHandler = (err, req, res, next) => {
    // Default error values
    let statusCode = err.statusCode || 500;
    let status = err.status || 'error';
    let message = err.message || 'Internal Server Error';
    const analysisId = err.analysisId || undefined;

    // Handle Express body-parser malformed JSON errors
    if (err.type === 'entity.parse.failed') {
        statusCode = 400;
        status = 'fail';
        message = 'Malformed JSON payload';
    }

    const response = {
        error: status,
        message: message
    };

    // Attach tracing ID to response if available
    if (analysisId) {
        response.analysisId = analysisId;
    }

    // Do NOT send stack traces or internal implementation details to the client.
    // Log operational errors to backend terminal to trace
    if (statusCode === 500 || statusCode === 501) {
        console.error(`[Error] ${analysisId ? `[ID: ${analysisId}] ` : ''}${err.message}`);
    }
    
    res.status(statusCode).json(response);
};

module.exports = errorHandler;
