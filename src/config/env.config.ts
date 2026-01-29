import dotenv from 'dotenv';
import { StringValue } from 'ms';

dotenv.config();

export const envConfig = {
    dbConfig: {
        host: process.env.DB_HOST || 'localhost',
        port: Number(process.env.DB_PORT) || 5432,
        user: process.env.DB_USER || 'postgres',
        password: String(process.env.DB_PASSWORD) || 'password',
        database: process.env.DB_NAME || 'auth_db',
    },

    serverConfig: {
        port: Number(process.env.SERVER_PORT) || 3000,
        nodeEnv: process.env.NODE_ENV || 'development',
        jwtSecret: process.env.JWT_SECRET || 'your_jwt_secret',
        bcryptSaltRounds: Number(process.env.BCRYPT_SALT_ROUNDS) || 10,
        frontendUrl: process.env.FRONTEND_URL || 'http://localhost:3000',
    },

    redisConfig: {
        host: process.env.REDIS_HOST || 'localhost',
        port: Number(process.env.REDIS_PORT) || 6379,
        password: process.env.REDIS_PASSWORD || undefined,
        db: Number(process.env.REDIS_DB) || 0,
        redisTTLDays: process.env.REDIS_TTL_DAYS ? parseInt(process.env.REDIS_TTL_DAYS) : 30,
    },

    tokenConfig: {
        accessTokenTTL: process.env.ACCESS_TOKEN_TTL ? (process.env.ACCESS_TOKEN_TTL as StringValue) : '15m',
        refreshTokenTTL: Number(process.env.REFRESH_TOKEN_TTL_DAYS) || 30,
        blackListAccessTokenTTLHours: Number(process.env.BLACKLISTED_ACCESS_TOKEN_TTL_HOURS) || 24,
        blackListRefreshTokenTTLDays: Number(process.env.BLACKLISTED_REFRESH_TOKEN_TTL_DAYS) || 30,
        resetPasswordTokenTTLHours: Number(process.env.RESET_PASSWORD_TOKEN_TTL_HOURS) || 1,
        maxSessionPerUser: Number(process.env.MAX_SESSIONS_PER_USER) || 5,
        refreshTokenLength: Number(process.env.REFRESH_TOKEN_LENGTH) || 64,
    },

    emailConfig: {
        host: process.env.SMTP_HOST || 'smtp.gmail.com',
        port: Number(process.env.SMTP_PORT) || 587,
        secure: process.env.SMTP_SECURE === 'true', // true for 465, false for other ports
        user: process.env.SMTP_USER || '',
        password: process.env.SMTP_PASSWORD || '',
        fromEmail: process.env.SMTP_FROM_EMAIL || process.env.SMTP_USER || '',
        fromName: process.env.SMTP_FROM_NAME || 'Auth Service',
    }
};

export const tokenConversions = {
    REFRESH_TOKEN_EXPIRY: {
        days: envConfig.redisConfig.redisTTLDays,
        seconds: envConfig.redisConfig.redisTTLDays * 24 * 60 * 60,
        miliseconds: envConfig.redisConfig.redisTTLDays * 24 * 60 * 60 * 1000,
    },

    REFRESH_TOKEN: {
        days: envConfig.tokenConfig.refreshTokenTTL,
        hours: envConfig.tokenConfig.refreshTokenTTL * 24,
        minutes: envConfig.tokenConfig.refreshTokenTTL * 24 * 60,
        seconds: envConfig.tokenConfig.refreshTokenTTL * 24 * 60 * 60,
        miliseconds: envConfig.tokenConfig.refreshTokenTTL * 24 * 60 * 60 * 1000,
    },

    BLACKLIST_ACCESS_TOKEN: {
        hours: envConfig.tokenConfig.blackListAccessTokenTTLHours,
        minutes: envConfig.tokenConfig.blackListAccessTokenTTLHours * 60,
        seconds: envConfig.tokenConfig.blackListAccessTokenTTLHours * 60 * 60,
        miliseconds: envConfig.tokenConfig.blackListAccessTokenTTLHours * 60 * 60 * 1000,
    },

    BLACKLIST_REFRESH_TOKEN: {
        days: envConfig.tokenConfig.blackListRefreshTokenTTLDays,
        hours: envConfig.tokenConfig.blackListRefreshTokenTTLDays * 24,
        minutes: envConfig.tokenConfig.blackListRefreshTokenTTLDays * 24 * 60,
        seconds: envConfig.tokenConfig.blackListRefreshTokenTTLDays * 24 * 60 * 60,
        miliseconds: envConfig.tokenConfig.blackListRefreshTokenTTLDays * 24 * 60 * 60 * 1000,
    },

    RESET_PASSWORD_TOKEN: {
        hours: envConfig.tokenConfig.resetPasswordTokenTTLHours,
        minutes: envConfig.tokenConfig.resetPasswordTokenTTLHours * 60,
        seconds: envConfig.tokenConfig.resetPasswordTokenTTLHours * 60 * 60,
        miliseconds: envConfig.tokenConfig.resetPasswordTokenTTLHours * 60 * 60 * 1000,
    }
}

