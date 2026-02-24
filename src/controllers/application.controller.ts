import { ApplicationService } from '@/services/application.services';
import logger from '@/utils/logger';
import { NextFunction, Request, Response } from 'express';
import { validationResult } from 'express-validator';

export const createApplication = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const errors = validationResult(req);
        const user = req.user as any;

        if (!errors.isEmpty()) {
            logger.warn('Validation errors during application creation', {
                errors: errors.array(),
                userId: user.userId,
                ip: req.ip
            });

            return res.status(422).json({
                success: false,
                message: 'Validation errors',
                data: errors.array()
            });
        }

        const { name, description, allowedOrigins, webhookUrl } = req.body;

        const newApplication = await ApplicationService.createApplication(
            name,
            description,
            allowedOrigins,
            webhookUrl
        );

        logger.info('Application created successfully', {
            applicationId: newApplication.id,
            applicationName: newApplication.name,
            createdBy: user.userId,
            ip: req.ip
        });

        return res.status(201).json({
            success: true,
            message: 'Application created successfully',
            data: {
                id: newApplication.id,
                name: newApplication.name,
                description: newApplication.description,
                apiKey: newApplication.apiKey,
                allowedOrigins: newApplication.allowedOrigins,
                webhookUrl: newApplication.webhookUrl,
                createdAt: newApplication.createdAt
            }
        });

    } catch (error: any) {
        logger.error('Error creating application', {
            error: error.message,
            stack: error.stack,
            ip: req.ip
        });
        next(error);
    }
};