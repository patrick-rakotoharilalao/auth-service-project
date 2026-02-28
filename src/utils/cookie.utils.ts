import { Response } from 'express';
import { envConfig, tokenConversions } from '@/config/env.config';

export const setAuthCookies = (res: Response, refreshToken: string, sessionId: string) => {
    const cookieOptions = {
        httpOnly: true,
        secure: envConfig.serverConfig.nodeEnv === 'production',
        maxAge: tokenConversions.REFRESH_TOKEN_EXPIRY.miliseconds,
        sameSite: envConfig.serverConfig.nodeEnv === 'production' ? 'none' : 'lax',
        path: '/'
    } as const;

    res.cookie('refreshToken', refreshToken, cookieOptions);
    res.cookie('sessionId', sessionId, cookieOptions);
};