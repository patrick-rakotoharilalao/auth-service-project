import { User } from '@/generated/prisma/client';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { envConfig, tokenConversions } from '../config/env.config';
import prisma from '../lib/prisma';
import logger from '../utils/logger';
import { EmailService } from './email.service';
import { redisService } from './redis.services';
import { InternalServerError, UnauthorizedError } from '../errors';

const BLACKLISTED_ACCESS_TOKEN_TTL_HOURS = process.env.BLACKLISTED_ACCESS_TOKEN_TTL_HOURS ? parseInt(process.env.BLACKLISTED_ACCESS_TOKEN_TTL_HOURS) : 24;
const BLACKLISTED_REFRESH_TOKEN_TTL_DAYS = process.env.BLACKLISTED_REFRESH_TOKEN_TTL_DAYS ? parseInt(process.env.BLACKLISTED_REFRESH_TOKEN_TTL_DAYS) : 30;
export class AuthService {
    static generateRefreshToken() {
        return crypto.randomBytes(40).toString('hex');
    }

    static async revokeToken(token: string, type: 'access' | 'refresh') {
        // Logic to blacklist the access token in Redis
        const TTL = type === 'access' ? BLACKLISTED_ACCESS_TOKEN_TTL_HOURS * 60 * 60 : BLACKLISTED_REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60;
        return await redisService.set(`blacklist:${token}`, true, TTL);

    }

    static async createUser(email: string, password: string) {
        try {
            const emailNormalized = email.toLowerCase();

            // Check email not already in DB
            const existingUser = await prisma.user.findUnique({
                where: { emailNormalized },
            });

            if (existingUser) {
                throw new Error('Email already in use');
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

            return newUser;
        } catch (error: any) {
            throw error;
        }
    }

    static async loginUser(email: string, password: string, context: { ip: string; userAgent: string }) {
        try {
            const user = await this.verifyCredentials(email, password);
            await this.enforceSessionLimits(user);
            await this.revokeSameDeviceSession(user.id, context.userAgent);
            const { refreshToken, refreshTokenHash } = await this.issueRefreshToken(user, context.ip);
            const session = await this.createSession(user.id, refreshTokenHash, context.userAgent);
            const accessToken = this.generateAccessToken(user, session.id);

            return { user, refreshToken, accessToken, session };
        } catch (error: any) {
            throw error;
        }
    }

    private static async verifyCredentials(email: string, password: string): Promise<User> {

        const emailNormalized = email.toLowerCase();
        // Attempt to find user by email
        const user = await prisma.user.findUnique({
            where: { emailNormalized: emailNormalized }
        });

        if (!user) {
            await bcrypt.compare(password, '$2b$10$fakehashforconstanttime'); // Hash factice
            throw new Error('Invalid email or password');
        }

        // Compare hashed password
        const isMatch = await bcrypt.compare(password, user.passwordHash);

        if (!isMatch) {
            throw new Error('Invalid email or password');
        }

        return user;
    }

    private static async enforceSessionLimits(user: User) {
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


    }

    private static async revokeSameDeviceSession(userId: string, device: string) {
        const sameSession = await prisma.session.findFirst({
            where: {
                userId: userId,
                deviceInfo: device,
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
    }

    private static async issueRefreshToken(user: User, ip: string) {
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
                ip: ip,
                issuedAt: Date.now()
            },
            tokenConversions.REFRESH_TOKEN_EXPIRY.seconds
        );

        return { refreshToken, refreshTokenHash };
    }

    private static async createSession(userId: string, refreshTokenHash: string, device: string) {

        // create session in DB
        const session = await prisma.session.create({
            data: {
                userId: userId,
                tokenHash: refreshTokenHash,
                deviceInfo: device,
                expiresAt: new Date(Date.now() + tokenConversions.REFRESH_TOKEN_EXPIRY.miliseconds), // 30 days
                revoked: false
            }
        });

        return session;
    }

    private static generateAccessToken(user: User, sessionId: string) {

        const payload = { userId: user.id, email: user.email, sessionId: sessionId };

        const accessToken = jwt.sign(
            payload,
            envConfig.serverConfig.jwtSecret,
            {
                expiresIn: envConfig.tokenConfig.accessTokenTTL,
                algorithm: 'HS256'
            }
        );

        return accessToken;
    }


    static async revokingData(sessionId: string, accessToken: string, refreshToken: string) {
        // revoke access token
        try {
            await this.revokeToken(accessToken, 'access');
        } catch (err) {
            throw new Error('Failed to revoke access token');
        }

        // revoke refresh token
        try {
            await this.revokeToken(refreshToken, 'refresh');
        } catch (err) {
            throw new Error('Failed to revoke refresh token');
        }

        // Revoke session in DB
        try {
            await prisma.session.update({
                where: { id: sessionId },
                data: { revoked: true }
            });
        } catch (err) {
            throw new Error('Failed to revoke session');
        }
    }

    static async forgotUserPassword(email: string) {
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
            throw new Error('User not found');
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

        // Build reset link
        const resetLink = `${envConfig.serverConfig.frontendUrl}/reset-password?token=${token}`;

        // Send password reset email
        try {
            await EmailService.sendPasswordResetEmail(user.email, resetLink);
            logger.info('Password reset email sent successfully', {
                email: user.email,
                userId: user.id,
            });
        } catch (error: any) {
            // Log error but don't fail the request (user still gets token in DB)
            // In production, you might want to handle this differently
            logger.error('Failed to send password reset email', {
                email: user.email,
                error: error.message,
            });
            // Optionally, you could throw here if email is critical
            // throw new Error('Failed to send password reset email');
        }

        // Don't return token for security - email contains the link
        return { success: true };
    }

    static async resetUserPassword(token: string, newPassword: string) {
        // get all token valid 
        const resetRecords = await prisma.passwordResets.findMany({
            where: { used: false, expiresAt: { gte: new Date() } }
        });

        if (!resetRecords.length) {
            throw new Error('Reset token not found or expired');
        }

        const match = resetRecords.find(r => bcrypt.compareSync(token, r.tokenHash));

        if (!match) {
            throw new Error('Invalid or already used reset token');
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

        return match;
    }

    static async refreshUserToken(sessionId: string, refreshToken: string) {
        // Verify refresh token in DB
        const session = await prisma.session.findUnique({
            where: { id: 'kfff' },
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
            throw new UnauthorizedError('Invalid refresh token');
        }

        if (session.revoked) {
            throw new UnauthorizedError('Session revoked');
        }

        // Verify that token matches the one in session
        const tokenMatched = await bcrypt.compare(refreshToken, session.tokenHash);
        if (!tokenMatched) {
            throw new UnauthorizedError('Invalid refresh token');
        }

        // Verify refresh token blacklist
        const blacklisted = await redisService.get(`blacklist:${refreshToken}`);
        if (blacklisted) {
            throw new UnauthorizedError('Refresh token invalid or expired');
        }

        // Verify refresh token TTL in Redis
        const refreshTokenTTL = await redisService.ttl(`refreshToken:${session.tokenHash}`);
        if (refreshTokenTTL === -2) {
            throw new UnauthorizedError('Refresh token expired on invalid');
        }

        if (refreshTokenTTL === -1) {
            throw new InternalServerError('Invalid refresh token configuration');
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
    }

}