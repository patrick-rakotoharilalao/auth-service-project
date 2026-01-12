import prisma from '../lib/prisma';
import { Request, Response } from 'express';
import { validationResult } from 'express-validator';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { AuthService } from '../services/auth.services';
import { redisService } from '../services/redis.services';
import logger from '../utils/logger';

const REDIS_TTL = process.env.REDIS_TTL ? parseInt(process.env.REDIS_TTL) : 30;
const REFRESH_TOKEN_EXPIRY_SECONDS = REDIS_TTL * 24 * 60 * 60; // 30 days

const TOKEN_CONFIG = {
    ACCESS_TOKEN_EXPIRY: '15m' as const,
    REFRESH_TOKEN_EXPIRY_DAYS: REDIS_TTL,
    MAX_SESSIONS_PER_USER: 5, // Limite de sessions simultanées
    REFRESH_TOKEN_LENGTH: 64 // Longueur du token en bytes
};

/**
 *  Register a new user
 * @param req 
 * @param res 
 */
export const register = async (req: Request, res: Response) => {
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

        // check email not in DB
        const user = await prisma.user.findUnique({
            where: { emailNormalized: emailNormalized },
        });

        if (user) {
            return res.status(400).json({
                success: false,
                message: 'Email already in use'
            });
        }

        // Hash password with bcrypt
        const hashedPassword = await bcrypt.hash(password, process.env.BCRYPT_SALT_ROUNDS ? parseInt(process.env.BCRYPT_SALT_ROUNDS) : 10);

        // Create user in DB
        const newUser = await prisma.user.create({
            data: {
                email: email,
                passwordHash: hashedPassword,
                emailNormalized: emailNormalized,
            },
            select: {
                id: true,
                email: true,
            }
        });

        return res.status(201).json({
            success: true,
            userId: newUser.id,
            message: `User registered with email: ${email}`
        });

    } catch (error) {
        console.error('Registration error:', error);
        return res.status(500).json({ message: 'Internal server error' });
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
            // Timing constant pour éviter les attaques temporelles
            await bcrypt.compare(password, '$2b$10$fakehashforconstanttime'); // Hash factice

            logger.warn('Login attempt with non-existent email', {
                email: emailNormalized,
                ip: req.ip
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

        // Generate JWT token
        const JWT_SECRET = process.env.JWT_SECRET;
        const payload = { userId: user.id, email: user.email };

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

        // Generate refresh token
        const refreshToken = crypto.randomBytes(TOKEN_CONFIG.REFRESH_TOKEN_LENGTH).toString('hex');
        const refreshTokenHash = await bcrypt.hash(refreshToken, 12);
        const refreshTokenExpiryMs = TOKEN_CONFIG.REFRESH_TOKEN_EXPIRY_DAYS * 24 * 60 * 60 * 100
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
            device: await getDeviceInfo(req) // Fonction à implémenter
        });

        // Successful login
        res.status(200).json({
            success: true,
            message: 'Login successful',
            data: {
                user: { userId: user.id, email: user.email },
                accessToken: token,
                refreshToken: refreshToken,
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

        // Ne pas révéler d'information sensible
        res.status(500).json({
            success: false,
            message: 'Authentication failed'
        });
    }
};

async function getDeviceInfo(req: Request): Promise<string> {
    return req.headers['user-agent'] || 'unknown';
}