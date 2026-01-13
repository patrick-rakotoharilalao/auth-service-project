import prisma from '../lib/prisma';
import { request, Request, Response } from 'express';
import { validationResult } from 'express-validator';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { AuthService } from '../services/auth.services';
import { redisService } from '../services/redis.services';
import logger from '../utils/logger';
import { StringValue } from 'ms'

const ACCESS_TOKEN_TTL = process.env.ACCESS_TOKEN_TTL ? (process.env.ACCESS_TOKEN_TTL as StringValue) : '15m';
const REDIS_TTL = process.env.REDIS_TTL_DAYS ? parseInt(process.env.REDIS_TTL_DAYS) : 30;
const REFRESH_TOKEN_EXPIRY_SECONDS = REDIS_TTL * 24 * 60 * 60; // 30 days
const RESET_PASSWORD_TOKEN_TTL_HOURS = process.env.RESET_PASSWORD_TOKEN_TTL_HOURS ? Number(process.env.RESET_PASSWORD_TOKEN_TTL_HOURS) : 1;

const TOKEN_CONFIG = {
    ACCESS_TOKEN_EXPIRY: ACCESS_TOKEN_TTL,
    REFRESH_TOKEN_EXPIRY_DAYS: REDIS_TTL,
    MAX_SESSIONS_PER_USER: 5, // Limite de sessions simultanées
    REFRESH_TOKEN_LENGTH: 64, // Longueur du token en bytes
    RESET_PASSWORD_EXPIRY_TTL_HOURS: RESET_PASSWORD_TOKEN_TTL_HOURS
};

/**
 *  Register a new user
 * @param req 
 * @param res 
 */
export const register = async (req: Request, res: Response) => {
    try {
        // Validate inputs
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            logger.warn('Validation errors during registration', { errors: errors.array() });
            return res.status(400).json({
                success: false,
                message: 'Validation errors',
                data: errors.array()
            });
        }

        const { email, password } = req.body;
        const emailNormalized = email.toLowerCase();

        // Check email not already in DB
        const existingUser = await prisma.user.findUnique({
            where: { emailNormalized },
        });

        if (existingUser) {
            logger.warn(`Email already in use during registration: ${email}`);
            return res.status(400).json({
                success: false,
                message: 'Email already in use'
            });
        }

        // Hash password with bcrypt
        const saltRounds = process.env.BCRYPT_SALT_ROUNDS ? parseInt(process.env.BCRYPT_SALT_ROUNDS) : 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Create user in DB
        const newUser = await prisma.user.create({
            data: {
                email,
                passwordHash: hashedPassword,
                emailNormalized
            },
            select: {
                id: true,
                email: true
            }
        });

        logger.info('User registered successfully', { userId: newUser.id, email });

        return res.status(201).json({
            success: true,
            userId: newUser.id,
            message: `User registered with email: ${email}`
        });

    } catch (error: any) {
        logger.error('Registration error', { error: error.message, stack: error.stack });
        return res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
};

/**
 * Login user
 * @param req 
 * @param res 
 */
export const login = async (req: Request, res: Response) => {
    try {
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                message: 'Validation errors',
                data: errors.array()
            });
        }

        const { email, password } = req.body;
        const emailNormalized = email.toLowerCase();

        // Verify email and password
        const user = await prisma.user.findUnique({
            where: { emailNormalized: emailNormalized },
        });

        if (!user) {
            // Constant timing to avoid time attacks
            await bcrypt.compare(password, '$2b$10$fakehashforconstanttime'); // Hash factice

            logger.warn('Login attempt with non-existent email', {
                email: emailNormalized,
                ip: req.ip // req.socket.remoteAddress if IPV4 needed
            });

            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        const passwordMatch = await bcrypt.compare(password, user.passwordHash);

        if (!passwordMatch) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });

        }

        // Verify limit sessions
        const activeSessions = await prisma.session.count({
            where: {
                userId: user.id,
                revoked: false,
                expiresAt: { gt: new Date() }
            }
        });


        if (activeSessions >= TOKEN_CONFIG.MAX_SESSIONS_PER_USER) {
            const oldestSession = await prisma.session.findFirst({
                where: {
                    userId: user.id,
                    revoked: false
                },
                orderBy: { createdAt: 'asc' },
                select: { tokenHash: true }
            });

            if (oldestSession) {
                await redisService.del(`refreshToken:${oldestSession.tokenHash}`);
                await prisma.session.update({
                    where: { tokenHash: oldestSession.tokenHash },
                    data: { revoked: true }
                });
            }
        }

        const sameSession = await prisma.session.findFirst({
            where: {
                userId: user.id,
                deviceInfo: req.headers['user-agent'] || 'unknown',
                revoked: false,
                expiresAt: { gt: new Date() }
            }
        });

        if (sameSession) {
            await prisma.session.update({
                where: { id: sameSession.id },
                data: { revoked: true }
            });
            await redisService.del(`refreshToken:${sameSession.tokenHash}`);
        }

        // Generate refresh token
        const refreshToken = crypto.randomBytes(TOKEN_CONFIG.REFRESH_TOKEN_LENGTH).toString('hex');
        const refreshTokenHash = await bcrypt.hash(refreshToken, 12);
        const refreshTokenExpiryMs = TOKEN_CONFIG.REFRESH_TOKEN_EXPIRY_DAYS * 24 * 60 * 60 * 1000
        const expiresAt = new Date(Date.now() + refreshTokenExpiryMs);

        // store refresh token in Redis
        await redisService.set(
            `refreshToken:${refreshTokenHash}`,
            {
                userId: user.id,
                email: user.email,
                expiresAt: expiresAt,
                ip: req.ip,
                issuedAt: Date.now()
            },
            TOKEN_CONFIG.REFRESH_TOKEN_EXPIRY_DAYS * 24 * 60 * 60
        );

        // create session in DB
        const session = await prisma.session.create({
            data: {
                userId: user.id,
                tokenHash: refreshTokenHash,
                deviceInfo: req.headers['user-agent'] || 'unknown',
                expiresAt: new Date(Date.now() + REFRESH_TOKEN_EXPIRY_SECONDS * 1000), // 30 days
                revoked: false
            }
        });

        logger.info('User logged in successfully', {
            userId: user.id,
            sessionId: session.id,
            ip: req.ip,
            device: req.headers['user-agent'] || 'unknown',
        });

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: TOKEN_CONFIG.REFRESH_TOKEN_EXPIRY_DAYS * 24 * 60 * 60 * 1000,
            sameSite: 'none'
        });

        // Generate JWT token
        const JWT_SECRET = process.env.JWT_SECRET;
        const payload = { userId: user.id, email: user.email, sessionId: session.id };

        if (!JWT_SECRET) {
            logger.error('JWT_SECRET is not configured');
            throw new Error('Server configuration error');
        }
        const token = jwt.sign(
            payload,
            JWT_SECRET,
            {
                expiresIn: TOKEN_CONFIG.ACCESS_TOKEN_EXPIRY,
                algorithm: 'HS256'
            }
        );

        // Successful login
        return res.status(200).json({
            success: true,
            message: 'Login successful',
            data: {
                user: { userId: user.id, email: user.email },
                accessToken: token,
                sessionId: session.id
            }
        });
    } catch (error: any) {
        logger.error('Login error', {
            error: error.message,
            stack: error.stack,
            email: req.body.email,
            ip: req.ip
        });

        // Do not disclose sensitive information
        return res.status(500).json({
            success: false,
            message: 'Authentication failed'
        });
    }
};

/**
 * Logout user
 * @param req 
 * @param res 
 */
export const logout = async (req: Request, res: Response) => {
    try {
        // blacklist the access and refresh token in Redis and mark session as revoked in DB
        logger.info('Logout request received', {
            ip: req.ip,
            userAgent: req.headers['user-agent'] || 'unknown',
        });

        const accessToken = (req as any).accessToken; // already verified in authenticate middleware
        const user = (req as any).user; // from authenticate middleware

        if (!user || !user.sessionId) {
            logger.warn('Invalid access token during logout', { user });
            return res.status(400).json({
                success: false,
                message: 'Invalid access token'
            });
        }

        const sessionId = user.sessionId;

        // Revoke access token
        try {
            await AuthService.revokeToken(accessToken, 'access');
        } catch (err) {
            logger.error('Failed to revoke access token', { error: (err as Error).message });
        }

        // Revoke refresh token
        const refreshToken = req.cookies.refreshToken;
        if (!refreshToken) {
            logger.warn('Refresh token missing during logout', { userId: user.id });
            return res.status(400).json({
                success: false,
                message: 'Refresh token is required for logout'
            });
        }

        try {
            await AuthService.revokeToken(refreshToken, 'refresh');
        } catch (err) {
            logger.error('Failed to revoke refresh token', { error: (err as Error).message });
        }

        // Revoke session in DB
        try {
            await prisma.session.update({
                where: { id: sessionId },
                data: { revoked: true }
            });
        } catch (err) {
            logger.error('Failed to revoke session in DB', { error: (err as Error).message, sessionId });
            return res.status(500).json({
                success: false,
                message: 'Failed to revoke session'
            });
        }

        // Clear refresh token cookie
        res.clearCookie('refreshToken', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'none'
        });

        // Return success response
        return res.status(200).json({
            success: true,
            message: 'Logout successful'
        });

    } catch (error: any) {
        logger.error('Logout error', {
            error: error.message,
            stack: error.stack,
            ip: req.ip
        });

        return res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
};

/**
 * Forgot password
 * @param req 
 * @param res 
 * @returns 
 */
export const forgotPassword = async (req: Request, res: Response) => {
    try {
        // Validate inputs
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            logger.warn('Validation errors during forgot password', { errors: errors.array() });
            return res.status(400).json({
                success: false,
                message: 'Validation errors',
                data: errors.array()
            });
        }

        const email = req.body.email;
        const emailNormalized = email.toLowerCase();

        // Find the user
        const user = await prisma.user.findUnique({
            where: { emailNormalized },
            select: {
                id: true,
                email: true,
                emailVerified: true
            }
        });

        if (!user) {
            logger.warn(`User not found for email: ${email}`);
            return res.status(404).json({
                success: false,
                message: `User not found for email: ${email}`
            });
        }

        // Generate secure token
        const token = crypto.randomBytes(TOKEN_CONFIG.REFRESH_TOKEN_LENGTH).toString('hex');
        const tokenHashed = await bcrypt.hash(token, 12);

        // Mark all previous password resets as used
        await prisma.passwordResets.updateMany({
            where: { userId: user.id, used: false },
            data: { used: true }
        });

        // Store new reset token
        const tokenExpiryMs = TOKEN_CONFIG.RESET_PASSWORD_EXPIRY_TTL_HOURS * 60 * 60 * 1000;
        const newResetPassword = await prisma.passwordResets.create({
            data: {
                tokenHash: tokenHashed,
                expiresAt: new Date(Date.now() + tokenExpiryMs),
                userId: user.id,
                used: false
            },
            select: {
                id: true,
                tokenHash: true,
                expiresAt: true,
                userId: true,
                createdAt: true,
                used: true
            }
        });

        // Send email for reset-password link // to implement later
        logger.info('Email reset-password sent, please check your email', {
            email: user.email,
            sentAt: new Date(),
            link: `https://frontend.com/reset-password?token=${token}`
        });

        return res.status(200).json({
            success: true,
            message: 'We have sent you an email to reset your password'
        });

    } catch (error: any) {
        logger.error('Internal server error during forgot password', {
            error: error.message,
            stack: error.stack
        });

        return res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: error.message
        });
    }
};

export const resetPassword = async (req: Request, res: Response) => {
    try {
        // 1️⃣ Validation des inputs
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            logger.warn('Validation errors during password reset', { errors: errors.array() });
            return res.status(400).json({
                success: false,
                message: 'Validation errors',
                errors: errors.array()
            });
        }

        const { token, newPassword } = req.body;

        // get all token valid 
        const resetRecords = await prisma.passwordResets.findMany({
            where: { used: false, expiresAt: { gte: new Date() } }
        });

        if (!resetRecords.length) {
            logger.info('No valid password reset token found', { token });
            return res.status(404).json({
                success: false,
                message: 'Reset token not found or expired'
            });
        }

        const match = resetRecords.find(r => bcrypt.compareSync(token, r.tokenHash));

        if (!match) {
            logger.warn('Invalid password reset token attempt', { token });
            return res.status(400).json({
                success: false,
                message: 'Invalid or already used reset token'
            });
        }

        // Update user password
        const hashedPassword = await bcrypt.hash(newPassword, 12);

        await prisma.user.update({
            where: { id: match.userId },
            data: { passwordHash: hashedPassword }
        });

        // Mark token as used
        await prisma.passwordResets.update({
            where: { id: match.id },
            data: { used: true }
        });

        logger.info('Password reset successfully', { userId: match.userId });

        return res.status(200).json({
            success: true,
            message: 'Password changed successfully'
        });

    } catch (error: any) {
        logger.error('Error resetting password', {
            error: error.message,
            stack: error.stack
        });

        return res.status(500).json({
            success: false,
            message: 'An unexpected error occurred while resetting password',
            error: error.message
        });
    }
};