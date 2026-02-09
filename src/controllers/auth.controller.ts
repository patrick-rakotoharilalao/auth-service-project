import bcrypt from 'bcrypt';
import crypto from 'crypto';
import { Request, Response } from 'express';
import { validationResult } from 'express-validator';
import jwt from 'jsonwebtoken';
import { envConfig, tokenConversions } from '../config/env.config';
import prisma from '../lib/prisma';
import { AuthService } from '../services/auth.services';
import { redisService } from '../services/redis.services';
import logger from '../utils/logger';
import { PasswordResets } from '../generated/prisma/client';


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


        if (activeSessions >= envConfig.tokenConfig.maxSessionPerUser) {
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
        const refreshToken = crypto.randomBytes(envConfig.tokenConfig.refreshTokenLength).toString('hex');
        const refreshTokenHash = await bcrypt.hash(refreshToken, 12);
        const expiresAt = new Date(Date.now() + tokenConversions.REFRESH_TOKEN_EXPIRY.miliseconds);

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
            tokenConversions.REFRESH_TOKEN_EXPIRY.seconds
        );

        // create session in DB
        const session = await prisma.session.create({
            data: {
                userId: user.id,
                tokenHash: refreshTokenHash,
                deviceInfo: req.headers['user-agent'] || 'unknown',
                expiresAt: new Date(Date.now() + tokenConversions.REFRESH_TOKEN_EXPIRY.miliseconds), // 30 days
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
            secure: envConfig.serverConfig.nodeEnv === 'production',
            maxAge: tokenConversions.REFRESH_TOKEN_EXPIRY.miliseconds,
            sameSite: envConfig.serverConfig.nodeEnv === 'production' ? 'none' : 'lax',
            path: '/'
        });

        res.cookie('sessionId', session.id, {
            httpOnly: true,
            secure: envConfig.serverConfig.nodeEnv === 'production',
            maxAge: tokenConversions.REFRESH_TOKEN_EXPIRY.miliseconds,
            sameSite: envConfig.serverConfig.nodeEnv === 'production' ? 'none' : 'lax',
            path: '/'
        });

        // Generate JWT token
        const payload = { userId: user.id, email: user.email, sessionId: session.id };

        const token = jwt.sign(
            payload,
            envConfig.serverConfig.jwtSecret,
            {
                expiresIn: envConfig.tokenConfig.accessTokenTTL,
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
            secure: envConfig.serverConfig.nodeEnv === 'production',
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
        const token = crypto.randomBytes(envConfig.tokenConfig.refreshTokenLength).toString('hex');
        const tokenHashed = await bcrypt.hash(token, 12);

        // Mark all previous password resets as used
        await prisma.passwordResets.updateMany({
            where: { userId: user.id, used: false },
            data: { used: true }
        });

        // Store new reset token
        await prisma.passwordResets.create({
            data: {
                tokenHash: tokenHashed,
                expiresAt: new Date(Date.now() + tokenConversions.RESET_PASSWORD_TOKEN.miliseconds),
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
            link: `${process.env.FRONTED_URL}/reset-password?token=${token}`
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
        // Validation des inputs
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
        const resetRecords: PasswordResets[] = await prisma.passwordResets.findMany({
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

export const refreshToken = async (req: Request, res: Response) => {
    try {

        const refreshToken = req.cookies.refreshToken;
        const sessionId = req.cookies.sessionId;
        if (!refreshToken) {
            logger.warn('Refresh token missing in cookie');
            return res.status(400).json({
                success: false,
                message: 'Refresh token is required'
            });
        }

        if (!sessionId) {
            logger.warn('Session Id missing in cookie');
            return res.status(400).json({
                success: false,
                message: 'Session Id is required'
            });
        }

        // Verify refresh token in DB
        const session = await prisma.session.findUnique({
            where: { id: sessionId },
            select: {
                id: true,
                userId: true,
                tokenHash: true,
                revoked: true,
                createdAt: true,
                user: true
            }
        });

        if (!session) {
            logger.warn('Session not found during refresh token');
            return res.status(401).json({
                success: false,
                message: 'Invalid refresh token'
            });
        }

        if (session.revoked) {
            logger.warn('Revoked session used during refresh token', { sessionId: session.id });
            return res.status(401).json({
                success: false,
                message: 'Session revoked'
            });
        }

        // Verify that token matches the one in session
        const tokenMatched = await bcrypt.compare(refreshToken, session.tokenHash);
        if (!tokenMatched) {
            logger.error('Refresh token does not match token hash in DB', {
                sessionId: session.id
            });
            return res.status(401).json({
                success: false,
                message: 'Invalid refresh token'
            });
        }

        // Verify refresh token blacklist
        const blacklisted = await redisService.get(`blacklist:${refreshToken}`);
        if (blacklisted) {
            logger.warn('Blacklisted refresh token used', { sessionId: session.id });
            return res.status(401).json({
                success: false,
                message: 'Refresh token invalid or expired'
            });
        }

        // Verify refresh token TTL in Redis
        const refreshTokenTTL = await redisService.ttl(`refreshToken:${session.tokenHash}`);
        if (refreshTokenTTL === -2) {
            logger.warn('Refresh token expired in Redis', { sessionId: session.id });
            return res.status(401).json({
                success: false,
                message: 'Refresh token expired or invalid'
            });
        }

        if (refreshTokenTTL === -1) {
            logger.error('Refresh token has no TTL in Redis', {
                sessionId: session.id
            });
            return res.status(500).json({
                success: false,
                message: 'Invalid refresh token configuration'
            });
        }

        // Generate a new access token
        const newPayload = {
            userId: session.userId,
            email: session.user.email,
            sessionId: session.id
        };

        const newAccessToken = jwt.sign(
            newPayload,
            envConfig.serverConfig.jwtSecret,
            {
                expiresIn: envConfig.tokenConfig.accessTokenTTL,
                algorithm: 'HS256'
            }
        );

        logger.info('Access token refreshed successfully', {
            sessionId: session.id,
            userId: session.userId
        });

        return res.status(200).json({
            success: true,
            message: 'Access token refreshed successfully',
            accessToken: newAccessToken
        });

    } catch (error: any) {
        logger.error('Refresh token error', {
            error: error.message,
            stack: error.stack
        });

        return res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
};

