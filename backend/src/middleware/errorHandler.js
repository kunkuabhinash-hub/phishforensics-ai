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

    // Handle Express body-parser malformed JSON errors
    if (err.type === 'entity.parse.failed') {
        statusCode = 400;
        status = 'fail';
        message = 'Malformed JSON payload';
    }

    // Do NOT send stack traces or internal implementation details to the client.
    // In a real app, you would log `err.stack` to an internal logger here.
    
    res.status(statusCode).json({
        error: status,
        message: message
    });
};

module.exports = errorHandler;
