import crypto from 'crypto';
import jwt from 'jsonwebtoken';

export class AuthService {
    static generateRefreshToken() {
        return crypto.randomBytes(40).toString('hex');
    }

}