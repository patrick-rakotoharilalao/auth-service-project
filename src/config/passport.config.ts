import passport from 'passport';
import { Strategy as GoogleStrategy, Profile, VerifyCallback } from 'passport-google-oauth20';
import { OAuthService } from '@/services/oauth.services';
import { InternalServerError } from '@/errors';

passport.use(
    new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_CLIENT_ID!,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
            callbackURL: process.env.GOOGLE_CALLBACK_URL!,
        },
        async (
            accessToken: string,
            refreshToken: string,
            profile: Profile,
            done: VerifyCallback
        ) => {
            try {
                const loginData = await OAuthService.authenticateWithOAuth(profile, accessToken, refreshToken);
                done(null, {
                    loginData
                });
            } catch (error) {
                console.error('Error in Google Strategy:', error);
                done(error as Error);
                throw new InternalServerError('Error in Google Strategy');
            }
        }
    )
);

export default passport;