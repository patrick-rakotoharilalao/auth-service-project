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

        // Create user in DB
        const newUser = await AuthService.createUser(email, password);

        logger.info('User registered successfully', { userId: newUser.id, email });

        return res.status(201).json({
            success: true,
            userId: newUser.id,
            message: `User registered with email: ${email}`
        });

    } catch (error: any) {
        if (error.message === 'Email already in use') {
            return res.status(400).json({
                success: false,
                message: 'Email already in use',
            });
        }

        logger.error('Registration error', { error: error.message, stack: error.stack });
        return res.status(500).json({
            success: false,
            message: 'Internal server error',
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
        const loginData = await AuthService.loginUser(email, password, { ip: req.ip || 'localhost', userAgent: req.headers['user-agent'] || 'unknown' });

        logger.info('User logged in successfully', {
            userId: loginData.user.id,
            sessionId: loginData.session.id,
            ip: req.ip,
            device: req.headers['user-agent'] || 'unknown',
        });

        res.cookie('refreshToken', loginData.refreshToken, {
            httpOnly: true,
            secure: envConfig.serverConfig.nodeEnv === 'production',
            maxAge: tokenConversions.REFRESH_TOKEN_EXPIRY.miliseconds,
            sameSite: envConfig.serverConfig.nodeEnv === 'production' ? 'none' : 'lax',
            path: '/'
        });

        res.cookie('sessionId', loginData.session.id, {
            httpOnly: true,
            secure: envConfig.serverConfig.nodeEnv === 'production',
            maxAge: tokenConversions.REFRESH_TOKEN_EXPIRY.miliseconds,
            sameSite: envConfig.serverConfig.nodeEnv === 'production' ? 'none' : 'lax',
            path: '/'
        });

        // Successful login
        return res.status(200).json({
            success: true,
            message: 'Login successful',
            data: {
                user: { userId: loginData.user.id, email: loginData.user.email },
                accessToken: loginData.accessToken,
                sessionId: loginData.session.id
            }
        });
    } catch (error: any) {
        if (error.message === 'Invalid email or password') {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

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

        const refreshToken = req.cookies.refreshToken;

        if (!refreshToken) {
            logger.warn('Refresh token missing during logout', { userId: user.id });
            return res.status(400).json({
                success: false,
                message: 'Refresh token is required for logout'
            });
        }

        await AuthService.revokingData(sessionId, accessToken, refreshToken);

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
            message: `Internal server error: ${error.message}`
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
        await AuthService.forgotUserPassword(email);
        
        // Always return same message for security (don't reveal if user exists)
        return res.status(200).json({
            success: true,
            message: 'If an account with that email exists, we have sent a password reset link.'
        });

    } catch (error: any) {
        logger.error('Internal server error during forgot password', {
            error: error.message,
            stack: error.stack
        });
        if (error.message === 'User not found') {
            return res.status(404).json({
                success: false,
                message: error.message
            });
        }

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

        const passwordReset = await AuthService.resetUserPassword(token, newPassword);

        logger.info('Password reset successfully', { userId: passwordReset.userId });

        return res.status(200).json({
            success: true,
            message: 'Password changed successfully'
        });

    } catch (error: any) {
        logger.error('Error resetting password', {
            error: error.message,
            stack: error.stack
        });

        if (error.message === 'Reset token not found or expired') {
            return res.status(404).json({
                success: false,
                message: error.message
            });
        }

        if (error.message === 'Invalid or already used reset token') {
            return res.status(400).json({
                success: false,
                message: error.message
            });
        }

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

