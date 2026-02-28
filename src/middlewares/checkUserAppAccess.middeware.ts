import { Request, Response, NextFunction } from 'express';
import prisma from '@/lib/prisma';
import logger from '@/utils/logger';
import { ForbiddenError } from '@/errors';

export const checkUserAppAccess = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const user = (req as any).user;
        const application = (req as any).application;

        if (!user || !application) {
            throw new ForbiddenError('Access denied');
        }

        const userAccess = await prisma.userAppAccess.findUnique({
            where: {
                userId_applicationId: {
                    userId: user.userId,
                    applicationId: application.id
                }
            }
        });

        if (!userAccess) {
            logger.warn('User does not have access to application', {
                userId: user.userId,
                applicationId: application.id,
                path: req.path,
                ip: req.ip
            });
            throw new ForbiddenError('You do not have access to this application');
        }

        (req as any).userAppAccess = userAccess;

        next();

    } catch (error) {
        next(error);
    }
};