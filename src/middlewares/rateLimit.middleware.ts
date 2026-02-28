import rateLimit from 'express-rate-limit';
import { TooManyRequestsError } from '@/errors';

const loginRegisterRateLimit = rateLimit({
    windowMs: 60 * 1000,
    max: process.env.LOGIN_REGISTER_RATE_LIMIT_MAX ? parseInt(process.env.LOGIN_REGISTER_RATE_LIMIT_MAX) : 10,
    standardHeaders: true,
    legacyHeaders: true,
    handler: () => {
        throw new TooManyRequestsError('Too many requests, please try again later.');
    }
});

const otherRateLimit = rateLimit({
    windowMs: 60 * 1000,
    max: process.env.OTHER_RATE_LIMIT_MAX ? parseInt(process.env.OTHER_RATE_LIMIT_MAX) : 100,
    standardHeaders: true,
    legacyHeaders: true,
    handler: () => {
        throw new TooManyRequestsError('Too many requests, please try again later.');
    }
});


export { loginRegisterRateLimit, otherRateLimit };

