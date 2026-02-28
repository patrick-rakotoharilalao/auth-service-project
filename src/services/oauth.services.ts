import { OAuthProfileInterface } from "@/interfaces/OAuthProfileInterface";
import prisma from "@/lib/prisma";
import { Profile } from "passport";
import { AuthService } from "./auth.services";
import { InternalServerError } from "@/errors";
import brcypt from 'bcrypt';
import crypto from 'crypto';

export class OAuthService {
    static async authenticateWithOAuth(profile: Profile, accessToken: string, refreshToken: string, appId: string) {
        const email = profile.emails?.[0].value;
        let user = await prisma.user.findFirst({
            where: {
                emailNormalized: email?.toLowerCase()
            }
        });

        const oauthProfile: OAuthProfileInterface = {
            provider: profile.provider,
            providerId: profile.id,
            accessToken,
            refreshToken,
            expiresAt: new Date()
        }

        if (!user) {
            user = await AuthService.createUser(email!, null, oauthProfile);
        }

        if (!user) {
            throw new InternalServerError('Failed to create user');
        }
        // login
        const loginData = await AuthService.loginUser(email!, null, { ip: 'undefined', userAgent: 'undefined' }, appId, 'oauth');
        // update oauth tokens
        await prisma.oAuthAccount.upsert({
            where: {
                userId: user.id,
                provider_providerId: {
                    provider: oauthProfile.provider,
                    providerId: oauthProfile.providerId
                }
            },
            update: {
                accessToken: oauthProfile.accessToken,
                refreshToken: oauthProfile.refreshToken,
                expiresAt: oauthProfile.expiresAt
            },
            create: {
                userId: user.id,
                provider: oauthProfile.provider,
                providerId: oauthProfile.providerId,
                accessToken: oauthProfile.accessToken,
                refreshToken: oauthProfile.refreshToken,
                expiresAt: oauthProfile.expiresAt
            }
        });
        return loginData;

    }

    static async generateBackupCode(userId: string) {
        const codes = [];
        const saltRounds = process.env.BCRYPT_SALT_ROUNDS ? parseInt(process.env.BCRYPT_SALT_ROUNDS) : 10;

        for (let i = 0; i < 10; i++) {
            const original = crypto.randomBytes(4).toString('hex').toUpperCase();
            const hashed = await brcypt.hash(original, saltRounds);
            const printed = `${original.slice(0, 4)}-${original.slice(4, 8)}`;

            await prisma.backupCode.create({
                data: {
                    userId: userId,
                    codeHash: hashed,
                }
            });

            codes.push({
                original,
                hashed,
                printed
            });
        }

        return codes;

    }
}