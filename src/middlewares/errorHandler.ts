import { Request, Response, NextFunction } from 'express';

/**
 * Global error handling middleware for Express
 * Must be registered AFTER all routes in app.ts
 * 
 * @param err - The error object thrown or passed via next(error)
 * @param req - Express request object
 * @param res - Express response object
 * @param next - Express next function (required for Express to recognize this as error middleware)
 */
export const errorHandler = (
    err: Error,
    req: Request,
    res: Response,
    next: NextFunction
): void => {

    // 1. Extract error properties (with defaults for non-custom errors)
    const statusCode = (err as any).statusCode || 500;
    const isOperational = (err as any).isOperational || false;

    // 2. Log the error (in production, use a proper logger like Winston or Pino)
    console.error('Error occurred:', {
        name: err.name,
        message: err.message,
        statusCode: statusCode,
        isOperational: isOperational,
        stack: err.stack,
        path: req.path,
        method: req.method
    });

    // 3. Send response to client
    res.status(statusCode).json({
        success: false,
        error: {
            name: err.name,
            message: err.message,
            // Include validation errors if available (for ValidationError)
            ...((err as any).errors && { errors: (err as any).errors }),
            // Only show stack trace in development mode
            ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
        }
    });

    // Note: We don't call next() here because we've sent the response
    // The request-response cycle ends here
};