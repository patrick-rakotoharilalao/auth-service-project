import crypto from 'crypto';
import { redisService } from './redis.services';

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

}