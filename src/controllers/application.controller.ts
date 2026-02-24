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

export const updateApplication = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const errors = validationResult(req);
        const user = req.user as any;
        const { id } = req.params;

        if (!errors.isEmpty()) {
            logger.warn('Validation errors during application update', {
                errors: errors.array(),
                applicationId: id,
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

        const updatedApplication = await ApplicationService.updateApplication(id, {
            name,
            description,
            allowedOrigins,
            webhookUrl
        });

        logger.info('Application updated successfully', {
            applicationId: updatedApplication.id,
            updatedBy: user.userId,
            ip: req.ip
        });

        return res.status(200).json({
            success: true,
            message: 'Application updated successfully',
            data: {
                id: updatedApplication.id,
                name: updatedApplication.name,
                description: updatedApplication.description,
                apiKey: maskApiKey(updatedApplication.apiKey),
                allowedOrigins: updatedApplication.allowedOrigins,
                webhookUrl: updatedApplication.webhookUrl,
                isActive: updatedApplication.isActive,
                updatedAt: updatedApplication.updatedAt
            }
        });

    } catch (error: any) {
        logger.error('Error updating application', {
            error: error.message,
            applicationId: req.params.id,
            ip: req.ip
        });
        next(error);
    }
};

export const regenerateApiKey = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const user = req.user as any;
        const { id } = req.params;

        const application = await ApplicationService.regenerateApiKey(id);

        logger.warn('API Key regenerated', {
            applicationId: application.id,
            applicationName: application.name,
            regeneratedBy: user.userId,
            ip: req.ip
        });

        return res.status(200).json({
            success: true,
            message: 'API Key regenerated successfully. Save it now, it will not be shown again.',
            data: {
                id: application.id,
                name: application.name,
                apiKey: application.apiKey,
                updatedAt: application.updatedAt
            }
        });

    } catch (error: any) {
        logger.error('Error regenerating API Key', {
            error: error.message,
            applicationId: req.params.id,
            ip: req.ip
        });
        next(error);
    }
};

export const toggleActive = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const user = req.user as any;
        const { id } = req.params;

        const application = await ApplicationService.toggleActive(id);

        logger.info('Application status toggled', {
            applicationId: application.id,
            applicationName: application.name,
            newStatus: application.isActive ? 'active' : 'inactive',
            toggledBy: user.userId,
            ip: req.ip
        });

        return res.status(200).json({
            success: true,
            message: `Application ${application.isActive ? 'activated' : 'deactivated'} successfully`,
            data: {
                id: application.id,
                name: application.name,
                isActive: application.isActive,
                updatedAt: application.updatedAt
            }
        });

    } catch (error: any) {
        logger.error('Error toggling application status', {
            error: error.message,
            applicationId: req.params.id,
            ip: req.ip
        });
        next(error);
    }
};

export const deleteApplication = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const user = req.user as any;
        const { id } = req.params;
        const { force } = req.query;

        const application = await ApplicationService.deleteApplication(
            id,
            force === 'true'
        );

        logger.warn('Application deleted', {
            applicationId: application.id,
            applicationName: application.name,
            usersCount: application.users.length,
            forced: force === 'true',
            deletedBy: user.userId,
            ip: req.ip
        });

        return res.status(200).json({
            success: true,
            message: 'Application deleted successfully',
            data: {
                id: application.id,
                name: application.name
            }
        });

    } catch (error: any) {
        logger.error('Error deleting application', {
            error: error.message,
            applicationId: req.params.id,
            ip: req.ip
        });
        next(error);
    }
};


export const getUsersByApp = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const user = req.user as any;
        const { id } = req.params;

        const userAccess = await ApplicationService.getUsersByApp(id);

        logger.info('Application users fetched', {
            applicationId: id,
            usersCount: userAccess.length,
            requestedBy: user.userId,
            ip: req.ip
        });

        return res.status(200).json({
            success: true,
            message: 'Application users retrieved successfully',
            data: userAccess.map(access => ({
                userId: access.user.id,
                email: access.user.email,
                role: access.role,
                emailVerified: access.user.emailVerified,
                userCreatedAt: access.user.createdAt
            }))
        });

    } catch (error: any) {
        logger.error('Error fetching application users', {
            error: error.message,
            applicationId: req.params.id,
            ip: req.ip
        });
        next(error);
    }
};

export const addUserToApp = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const errors = validationResult(req);
        const admin = req.user as any;
        const { id } = req.params;

        if (!errors.isEmpty()) {
            logger.warn('Validation errors during user addition to app', {
                errors: errors.array(),
                applicationId: id,
                adminId: admin.userId,
                ip: req.ip
            });

            return res.status(422).json({
                success: false,
                message: 'Validation errors',
                data: errors.array()
            });
        }

        const { userId, role } = req.body;

        const userAccess = await ApplicationService.addUserToApp(id, userId, role);

        logger.info('User added to application', {
            applicationId: id,
            userId: userAccess.userId,
            userEmail: userAccess.user.email,
            role: userAccess.role,
            addedBy: admin.userId,
            ip: req.ip
        });

        return res.status(201).json({
            success: true,
            message: 'User added to application successfully',
            data: {
                userId: userAccess.userId,
                userEmail: userAccess.user.email,
                applicationId: userAccess.applicationId,
                role: userAccess.role,
                createdAt: userAccess.addedAt
            }
        });

    } catch (error: any) {
        logger.error('Error adding user to application', {
            error: error.message,
            applicationId: req.params.id,
            ip: req.ip
        });
        next(error);
    }
};

export const removeUserFromApp = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const admin = req.user as any;
        const { id, userId } = req.params;

        const userAccess = await ApplicationService.removeUserFromApp(id, userId);

        logger.info('User removed from application', {
            applicationId: id,
            userId: userAccess.userId,
            userEmail: userAccess.user.email,
            removedBy: admin.userId,
            ip: req.ip
        });

        return res.status(200).json({
            success: true,
            message: 'User removed from application successfully',
            data: {
                userId: userAccess.userId,
                userEmail: userAccess.user.email,
                applicationId: userAccess.applicationId
            }
        });

    } catch (error: any) {
        logger.error('Error removing user from application', {
            error: error.message,
            applicationId: req.params.id,
            userId: req.params.userId,
            ip: req.ip
        });
        next(error);
    }
};