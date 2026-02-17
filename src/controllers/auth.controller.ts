import { NextFunction, Request, Response } from 'express';
import { validationResult } from 'express-validator';
import { envConfig } from '../config/env.config';
import { BadRequestError, NotFoundError, UnauthorizedError } from '../errors';
import { AuthService } from '../services/auth.services';
import { setAuthCookies } from '../utils/cookie.utils';
import logger from '../utils/logger';
import crypto from 'crypto';
import prisma from '../lib/prisma';
import * as qrcode from 'qrcode';
import speakeasy from 'speakeasy';
import { OAuthService } from '../services/oauth.services';

/**
 *  Register a new user
 * @param req 
 * @param res 
 */
export const register = async (req: Request, res: Response, next: NextFunction) => {
    try {
        // Validate inputs
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            logger.warn('Validation errors during registration', { errors: errors.array() });
            return res.status(422).json({
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
        next(error);
    }
};

/**
 * Login user
 * @param req 
 * @param res 
 */
export const login = async (req: Request, res: Response, next: NextFunction) => {
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

        if (loginData.requiresMfa) {
            return res.status(200).json({
                success: true,
                loginData
            });
        } else {
            setAuthCookies(res, loginData.refreshToken!, loginData.session?.id!);

            logger.info('User logged in successfully', {
                userId: loginData.user?.id,
                sessionId: loginData.session?.id,
                ip: req.ip,
                device: req.headers['user-agent'] || 'unknown',
            });

            // Successful login
            return res.status(200).json({
                success: true,
                message: 'Login successful',
                data: {
                    user: { userId: loginData.user?.id, email: loginData.user?.email },
                    accessToken: loginData.accessToken,
                    sessionId: loginData.session?.id
                }
            });
        }


    } catch (error: any) {
        next(error);
    }
};

export const verifyMfaLogin = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                message: 'Validation errors',
                data: errors.array()
            });
        }

        const { tempToken } = req.body;
        const loginData = await AuthService.completeMfaLogin(tempToken, { ip: req.ip || 'localhost', userAgent: req.headers['user-agent'] || 'unknown' });

        setAuthCookies(res, loginData.refreshToken!, loginData.session?.id!);

        logger.info('User logged in successfully', {
            userId: loginData.user.id,
            sessionId: loginData.session.id,
            ip: req.ip,
            device: req.headers['user-agent'] || 'unknown',
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
        next(error);
    }
}

/**
 * Logout user
 * @param req 
 * @param res 
 */
export const logout = async (req: Request, res: Response, next: NextFunction) => {
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
            throw new UnauthorizedError('Invalid access token');
        }

        const sessionId = user.sessionId;

        const refreshToken = req.cookies.refreshToken;

        if (!refreshToken) {
            logger.warn('Refresh token missing during logout', { userId: user.id });
            throw new UnauthorizedError('Refresh token is required for logout');
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

        next(error);
    }
};

/**
 * Forgot password
 * @param req 
 * @param res 
 * @returns 
 */
export const forgotPassword = async (req: Request, res: Response, next: NextFunction) => {
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
        next(error);
    }
};

/**
 * Reset User Password
 * @param req 
 * @param res 
 * @param next 
 * @returns 
 */
export const resetPassword = async (req: Request, res: Response, next: NextFunction) => {
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

        next(error);
    }
};

/**
 * Refresh User Token
 * @param req 
 * @param res 
 * @param next 
 * @returns 
 */
export const refreshToken = async (req: Request, res: Response, next: NextFunction) => {
    try {

        const refreshToken = req.cookies.refreshToken;
        const sessionId = req.cookies.sessionId;
        if (!refreshToken) {
            throw new BadRequestError('Refresh token missing in cookie');
        }

        const newAccessToken = await AuthService.refreshUserToken(sessionId, refreshToken);

        logger.info('Access token refreshed successfully', {
            sessionId: sessionId
        });

        return res.status(200).json({
            success: true,
            message: 'Access token refreshed successfully',
            accessToken: newAccessToken
        });

    } catch (error: any) {
        next(error);
    }
};

/**
 * Setting up 2-factoring authentication
 * @param req 
 * @param res 
 * @param next 
 */
export const setup2FA = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const userId = (req.user as any).userId;
        const email = (req.user as any).email;
        const appName = 'AppName';
        const emailEncoded = encodeURIComponent(email);
        const appNameEncoded = encodeURIComponent(appName);
        // Générer le secret TOTP
        const secret = speakeasy.generateSecret({
            name: `YourAppName:${emailEncoded}`
        });

        // Stocker en DB
        await prisma.user.update({
            where: { id: userId },
            data: { mfaSecret: secret.base32 }
        });

        // Créer l'URI TOTP
        const otpauth = `otpauth://totp/${appNameEncoded}:${emailEncoded}?secret=${secret.base32}&issuer=${appNameEncoded}`;

        // Générer le QR code en base64
        const qrCodeBase64 = await qrcode.toDataURL(otpauth);

        res.json({
            success: true,
            secret,
            otpauth,
            qrCode: qrCodeBase64
        });

    } catch (error) {
        next(error);
    }
};

/**
 * Verify 2-factoring authentication TOTP code
 * @param req 
 * @param res 
 * @param next 
 * @returns 
 */
export const verify2FA = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { code } = req.body;
        const userId = (req.user as any).userId;
        let isValid = false;
        const user = await prisma.user.findFirst({
            where: { id: userId },
        });
        if (user && user.mfaSecret) {
            isValid = speakeasy.totp.verify({
                secret: user?.mfaSecret,
                encoding: 'base32',
                token: code,
                window: 1
            });

        } else {
            throw new NotFoundError('User not found');
        }

        if (isValid) {

            await prisma.user.update({
                where: { id: user.id },
                data: { mfaEnabled: true }
            });

            const codes = await OAuthService.generateBackupCode(userId);

            return res.status(200).json({
                success: true,
                message: 'Multi-factoring authentication enabled successfully',
                backupCodes: codes
            });
        } else {
            throw new UnauthorizedError('Invalid TOTP code');
        }


    } catch (error) {
        next(error);
    }
}
