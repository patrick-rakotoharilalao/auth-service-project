import { NextFunction, Request, Response } from 'express';
import { validationResult } from 'express-validator';
import { UnauthorizedError } from '@/errors';
import { AuthService } from '@/services/auth.services';
import logger from '@/utils/logger';
import speakeasy from 'speakeasy';
import prisma from '@/lib/prisma';
import qrcode from 'qrcode';
import { NotFoundError } from '@/errors';
import { OAuthService } from '@/services/oauth.services';
import { setAuthCookies } from '@/utils/cookie.utils';
import { MfaService } from '@/services/mfa.services';


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

/**
 * Disable 2-factoring authentication
 * @param req 
 * @param res 
 * @param next 
 * @returns 
 */
export const disable2FA = async (req: Request, res: Response, next: NextFunction) => {
    try {
        // Validate inputs
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            logger.warn('Validation errors', { errors: errors.array() });
            return res.status(400).json({
                success: false,
                message: 'Validation errors',
                data: errors.array()
            });
        }

        const { password } = req.body;
        const email = (req.user as any).email;

        await MfaService.disable2Fa(email, password);

        return res.status(200).json({
            success: true,
            message: 'Multi-factoring authentication disabled successfully',
        });
    } catch (error) {
        next(error);
    }
}

/**
 * Second step of 2fa login
 * @param req 
 * @param res 
 * @param next 
 * @returns 
 */
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

        const { tempToken, code } = req.body;
        const loginData = await AuthService.completeMfaLogin(tempToken, { ip: req.ip || 'localhost', userAgent: req.headers['user-agent'] || 'unknown' }, code);

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