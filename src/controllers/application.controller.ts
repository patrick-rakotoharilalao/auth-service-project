import { ApplicationService } from '@/services/application.services';
import { maskApiKey } from '@/utils/apiKey.utils';
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

export const getAllApplications = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const user = req.user as any;
        const { isActive } = req.query;

        const applications = await ApplicationService.getAllApplications(
            isActive === 'true' ? true : isActive === 'false' ? false : undefined
        );

        logger.info('Applications fetched successfully', {
            count: applications.length,
            requestedBy: user.userId,
            filter: isActive ? `isActive=${isActive}` : 'none',
            ip: req.ip
        });

        return res.status(200).json({
            success: true,
            message: 'Applications retrieved successfully',
            data: applications.map(app => ({
                id: app.id,
                name: app.name,
                description: app.description,
                apiKey: maskApiKey(app.apiKey),
                allowedOrigins: app.allowedOrigins,
                webhookUrl: app.webhookUrl,
                isActive: app.isActive,
                createdAt: app.createdAt,
                updatedAt: app.updatedAt
            }))
        });

    } catch (error: any) {
        logger.error('Error fetching applications', {
            error: error.message,
            stack: error.stack,
            ip: req.ip
        });
        next(error);
    }
};

export const getApplicationById = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const user = req.user as any;
        const { id } = req.params;

        const application = await ApplicationService.getApplicationById(id);

        logger.info('Application fetched successfully', {
            applicationId: application.id,
            requestedBy: user.userId,
            ip: req.ip
        });

        return res.status(200).json({
            success: true,
            message: 'Application retrieved successfully',
            data: {
                id: application.id,
                name: application.name,
                description: application.description,
                apiKey: maskApiKey(application.apiKey),
                allowedOrigins: application.allowedOrigins,
                webhookUrl: application.webhookUrl,
                isActive: application.isActive,
                createdAt: application.createdAt,
                updatedAt: application.updatedAt
            }
        });

    } catch (error: any) {
        logger.error('Error fetching application', {
            error: error.message,
            applicationId: req.params.id,
            ip: req.ip
        });
        next(error);
    }
};