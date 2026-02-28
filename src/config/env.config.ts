import dotenv from 'dotenv';
import { StringValue } from 'ms';

dotenv.config();

function requireEnv(name: string): string {
    const value = process.env[name];
    if (!value) {
        throw new Error(`Missing required environment variable: ${name}`);
    }
    return value;
}

function validateEnv() {
    const requiredVars = [
        'JWT_SECRET',
        'SMTP_USER',
        'SMTP_PASSWORD',
    ];

    const missing = requiredVars.filter(name => !process.env[name]);

    if (missing.length > 0) {
        console.error(`Missing required environment variables: ${missing.join(', ')}`);
        process.exit(1);
    }
}

validateEnv();

// Helper to parse numbers with fallback
const getNumber = (key: string, fallback: number): number => {
    const value = process.env[key];
    return value ? Number(value) : fallback;
};

// Helper to parse booleans
const getBoolean = (key: string, fallback: boolean = false): boolean => {
    return process.env[key] === 'true' || fallback;
};

export const envConfig = {
    dbConfig: {
        host: process.env.DB_HOST || 'localhost',
        port: getNumber('DB_PORT', 5432),
        user: process.env.DB_USER || 'postgres',
        password: process.env.DB_PASSWORD || 'password',
        database: process.env.DB_NAME || 'auth_db',
    },

    serverConfig: {
        port: getNumber('SERVER_PORT', 3000),
        nodeEnv: process.env.NODE_ENV || 'development',
        jwtSecret: requireEnv('JWT_SECRET'),
        bcryptSaltRounds: getNumber('BCRYPT_SALT_ROUNDS', 10),
        frontendUrl: process.env.FRONTEND_URL || 'http://localhost:3000',
    },

    redisConfig: {
        host: process.env.REDIS_HOST || 'localhost',
        port: getNumber('REDIS_PORT', 6379),
        password: process.env.REDIS_PASSWORD,
        db: getNumber('REDIS_DB', 0),
        redisTTLDays: getNumber('REDIS_TTL_DAYS', 30),
        redisUrl: process.env.REDIS_URL,
    },

    tokenConfig: {
        accessTokenTTL: (process.env.ACCESS_TOKEN_TTL as StringValue) || '15m',
        refreshTokenTTL: getNumber('REFRESH_TOKEN_TTL_DAYS', 30),
        blackListAccessTokenTTLHours: getNumber('BLACKLISTED_ACCESS_TOKEN_TTL_HOURS', 24),
        blackListRefreshTokenTTLDays: getNumber('BLACKLISTED_REFRESH_TOKEN_TTL_DAYS', 30),
        resetPasswordTokenTTLHours: getNumber('RESET_PASSWORD_TOKEN_TTL_HOURS', 1),
        maxSessionPerUser: getNumber('MAX_SESSIONS_PER_USER', 5),
        refreshTokenLength: getNumber('REFRESH_TOKEN_LENGTH', 64),
    },

    emailConfig: {
        host: process.env.SMTP_HOST || 'smtp.gmail.com',
        port: getNumber('SMTP_PORT', 587),
        secure: getBoolean('SMTP_SECURE'),
        user: requireEnv('SMTP_USER'),
        password: requireEnv('SMTP_PASSWORD'),
        fromEmail: process.env.SMTP_FROM_EMAIL || requireEnv('SMTP_USER'),
        fromName: process.env.SMTP_FROM_NAME || 'Auth Service',
    },

    oauthConfig: {
        googleClientId: requireEnv('GOOGLE_CLIENT_ID'),
        googleClientSecret: requireEnv('GOOGLE_CLIENT_SECRET'),
        googleCallbackUrl: requireEnv('GOOGLE_CALLBACK_URL'),
    }
};

// Helper for time conversions from days
const createTimeConversions = (days: number) => ({
    days,
    hours: days * 24,
    minutes: days * 24 * 60,
    seconds: days * 24 * 60 * 60,
    miliseconds: days * 24 * 60 * 60 * 1000,
});

// Helper for time conversions from hours
const createTimeConversionsFromHours = (hours: number) => ({
    hours,
    minutes: hours * 60,
    seconds: hours * 60 * 60,
    miliseconds: hours * 60 * 60 * 1000,
});

export const tokenConversions = {
    REFRESH_TOKEN_EXPIRY: createTimeConversions(envConfig.redisConfig.redisTTLDays),
    REFRESH_TOKEN: createTimeConversions(envConfig.tokenConfig.refreshTokenTTL),
    BLACKLIST_ACCESS_TOKEN: createTimeConversionsFromHours(envConfig.tokenConfig.blackListAccessTokenTTLHours),
    BLACKLIST_REFRESH_TOKEN: createTimeConversions(envConfig.tokenConfig.blackListRefreshTokenTTLDays),
    RESET_PASSWORD_TOKEN: createTimeConversionsFromHours(envConfig.tokenConfig.resetPasswordTokenTTLHours),
};