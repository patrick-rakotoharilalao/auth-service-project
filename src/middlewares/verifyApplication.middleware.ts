import { Request, Response, NextFunction } from 'express';
import prisma from '@/lib/prisma';
import { ForbiddenError, UnauthorizedError } from '@/errors';
import logger from '@/utils/logger';

export const verifyApplication = async (req: Request, res: Response, next: NextFunction) => {
    try {
        // Extract API Key from header
        const apiKey = req.headers['x-api-key'] as string;

        if (!apiKey) {
            logger.warn('Missing API Key', {
                path: req.path,
                ip: req.ip
            });
            throw new UnauthorizedError('API Key is required');
        }

        // Find application by API Key
        const application = await prisma.application.findUnique({
            where: { apiKey }
        });

        if (!application) {
            logger.warn('Invalid API Key', {
                apiKey: apiKey.slice(0, 10) + '***',
                path: req.path,
                ip: req.ip
            });
            throw new UnauthorizedError('Invalid API Key');
        }

        // Check if application is active
        if (!application.isActive) {
            logger.warn('Application is inactive', {
                applicationId: application.id,
                applicationName: application.name,
                path: req.path,
                ip: req.ip
            });
            throw new ForbiddenError('Application is inactive');
        }

        // Verify CORS (allowed origins)
        const origin = req.headers.origin;
        if (origin && !application.allowedOrigins.includes(origin)) {
            logger.warn('Origin not allowed', {
                applicationId: application.id,
                origin,
                allowedOrigins: application.allowedOrigins,
                ip: req.ip
            });
            return res.status(403).json({
                success: false,
                message: 'Origin not allowed'
            });
        }

        // Store application in request
        (req as any).application = application;

        next();

    } catch (error) {
        next(error);
    }
};