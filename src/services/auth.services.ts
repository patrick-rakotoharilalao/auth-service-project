import bcrypt from 'bcrypt';
import crypto from 'crypto';
import { Request } from 'express';
import { envConfig, tokenConversions } from '../config/env.config';
import prisma from '../lib/prisma';
import { redisService } from './redis.services';
import jwt from 'jsonwebtoken';
import { User } from '@/generated/prisma/client';

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

    static async loginUser(email: string, password: string, context: {ip: string; userAgent: string}) {
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

    static async verifyCredentials(email: string, password: string): Promise<User> {

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

    static async enforceSessionLimits(user: User) {
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

    static async revokeSameDeviceSession(userId: string, device: string) {
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

    static async issueRefreshToken(user: User, ip: string) {
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

    static async createSession(userId: string, refreshTokenHash: string, device: string) {

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

    static generateAccessToken(user: User, sessionId: string) {

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

}