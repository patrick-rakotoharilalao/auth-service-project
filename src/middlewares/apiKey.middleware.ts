import { BadRequestError } from "@/errors";
import { Request, Response, NextFunction } from "express";

export const extractApiKeyFromState = (req: Request, res: Response, next: NextFunction) => {
    try {
        const { state } = req.query;

        if (!state) {
            throw new BadRequestError('Missing state parameter');
        }

        const decoded = JSON.parse(Buffer.from(state as string, 'base64').toString());

        req.headers['x-api-key'] = decoded.apiKey;

        next();
    } catch (error) {
        return res.status(400).json({ error: 'Invalid state parameter' });
    }
};