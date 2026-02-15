import { NextFunction, Request, Response } from 'express';
import passport from '../config/passport.config';
import logger from '../utils/logger';
import { setAuthCookies } from '../utils/cookie.utils';

/**
 * Initiate Google OAuth authentication
 */
export const googleAuth = passport.authenticate('google', {
    scope: ['profile', 'email'],
    accessType: 'offline',
    prompt: 'consent',
    session: false,
});

/**
 * Handle Google OAuth callback
 */
export const googleCallback = async (req: Request, res: Response, next: NextFunction) => {
    try {
        // Redirect to frontend app
        const { loginData } = req.user as any;
        console.log('session:', loginData);
        setAuthCookies(res, loginData.refreshToken, loginData.session.id);
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
    } catch (error) {
        logger.error('Error in Google callback', { error });
        next(error);
    }
};