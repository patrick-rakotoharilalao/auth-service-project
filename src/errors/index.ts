// 400 - Bad Request
class BadRequestError extends Error {
    public readonly statusCode: number;
    public readonly isOperational: boolean;

    constructor(message: string = 'Bad Request') {
        super(message);
        this.name = 'BadRequestError';
        this.statusCode = 400;
        this.isOperational = true;
    }
}

// 401 - Unauthorized 
class UnauthorizedError extends Error {
    public readonly statusCode: number;
    public readonly isOperational: boolean;

    constructor(message: string = 'Unauthorized') {
        super(message);
        this.name = 'UnauthorizedError';
        this.statusCode = 401;
        this.isOperational = true;
    }
}

// 403 - Forbidden
class ForbiddenError extends Error {
    public readonly statusCode: number;
    public readonly isOperational: boolean;

    constructor(message: string = 'Forbidden') {
        super(message);
        this.name = 'ForbiddenError';
        this.statusCode = 403;
        this.isOperational = true;
    }
}

// 404 - Not Found
class NotFoundError extends Error {
    public readonly statusCode: number;
    public readonly isOperational: boolean;

    constructor(message: string = 'Resource not found') {
        super(message);
        this.name = 'NotFoundError';
        this.statusCode = 404;
        this.isOperational = true;
    }
}

// 409 - Conflict
class ConflictError extends Error {
    public readonly statusCode: number;
    public readonly isOperational: boolean;

    constructor(message: string = 'Conflict') {
        super(message);
        this.name = 'ConflictError';
        this.statusCode = 409;
        this.isOperational = true;
    }
}

// 422 - Unprocessable Entity (Validation)
class ValidationError extends Error {
    public readonly statusCode: number;
    public readonly isOperational: boolean;
    public readonly errors?: Record<string, string>;

    constructor(message: string = 'Validation failed', errors?: Record<string, string>) {
        super(message);
        this.name = 'ValidationError';
        this.statusCode = 422;
        this.isOperational = true;
        this.errors = errors;
    }
}

// 429 - Too Many Requests
class TooManyRequestsError extends Error {
    public readonly statusCode: number;
    public readonly isOperational: boolean;

    constructor(message: string = 'Too many requests') {
        super(message);
        this.name = 'TooManyRequestsError';
        this.statusCode = 429;
        this.isOperational = true;
    }
}

// 500 - Internal Server Error
class InternalServerError extends Error {
    public readonly statusCode: number;
    public readonly isOperational: boolean;

    constructor(message: string = 'Internal server error') {
        super(message);
        this.name = 'InternalServerError';
        this.statusCode = 500;
        this.isOperational = false; // Not operational - unexpected error
    }
}

// 503 - Service Unavailable
class ServiceUnavailableError extends Error {
    public readonly statusCode: number;
    public readonly isOperational: boolean;

    constructor(message: string = 'Service unavailable') {
        super(message);
        this.name = 'ServiceUnavailableError';
        this.statusCode = 503;
        this.isOperational = true;
    }
}

// Export all errors
export {
    BadRequestError,
    UnauthorizedError,
    ForbiddenError,
    NotFoundError,
    ConflictError,
    ValidationError,
    TooManyRequestsError,
    InternalServerError,
    ServiceUnavailableError
};