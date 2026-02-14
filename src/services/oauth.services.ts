import { OAuthProfileInterface } from "@/interfaces/OAuthProfileInterface";
import prisma from "../lib/prisma";
import { Profile } from "passport";
import { AuthService } from "./auth.services";
import { InternalServerError } from "../errors";

export class OAuthService {
    static async authenticateWithOAuth (profile: Profile, accessToken: string, refreshToken: string) {
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
        const loginData = await AuthService.loginUser(email!, null, { ip: 'undefined', userAgent: 'undefined' }, 'oauth');
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
}