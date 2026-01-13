import logger from "../utils/logger";
import { NextFunction, Request, Response } from "express";
import jwt, { TokenExpiredError } from "jsonwebtoken";

const JWT_SECRET = process.env.JWT_SECRET as string;

/**
 * authenticate middleware to protect routes
 * @param req 
 * @param res 
 * @param next 
 * @returns 
 */
export const authenticate = (req: Request, res: Response, next: NextFunction) => {
    try {

        // Verify access token in headers (Bearer token)
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        const accessToken = authHeader.split(' ')[1];
        const payload = jwt.verify(accessToken, JWT_SECRET as string);
        (req as any).accessToken = accessToken;
        (req as any).user = payload;
        next();

    } catch (error: any) {
        logger.error('Authentication error', {
            error: error.message,
            stack: error.stack,
            ip: req.ip
        });
        if (error instanceof TokenExpiredError) {
            return res.status(401).json({ message: 'Access token expired' });
        }
    }
}