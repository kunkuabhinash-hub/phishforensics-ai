class AppError extends Error {
    constructor(message, statusCode) {
        super(message);
        this.statusCode = statusCode;
        
        // Determine status string based on HTTP code (4xx = fail, 5xx = error)
        this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
        this.isOperational = true;

        // Capture stack trace for internal logging, but won't be sent to client
        Error.captureStackTrace(this, this.constructor);
    }
}

module.exports = AppError;
