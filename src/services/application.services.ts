import { BadRequestError, NotFoundError } from "@/errors";
import prisma from "@/lib/prisma";
import crypto from 'crypto';

export class ApplicationService {
    static async createApplication(
        name: string, description: string | null = null,
        allowedOrigins: string[], webhookUrl: string) {

        const apiKey = this.generateApiKey();
        const newApplication = await prisma.application.create({
            data: {
                name,
                description,
                allowedOrigins,
                webhookUrl,
                apiKey
            }
        });

        return newApplication;
    }

    private static generateApiKey(): string {
        return `app_${crypto.randomBytes(32).toString('hex')}`;
    }

    static async getAllApplications(isActive?: boolean) {
        const applications = await prisma.application.findMany({
            where: isActive !== undefined ? { isActive } : {},
            orderBy: {
                createdAt: 'desc'
            }
        });

        return applications;
    }

    static async getApplicationById(id: string) {
        const application = await prisma.application.findUnique({
            where: { id }
        });

        if (!application) {
            throw new NotFoundError('Application not found');
        }

        return application;
    }

    static async updateApplication(
        id: string,
        data: {
            name?: string;
            description?: string | null;
            allowedOrigins?: string[];
            webhookUrl?: string | null;
        }
    ) {
        const application = await prisma.application.findUnique({
            where: { id }
        });

        if (!application) {
            throw new NotFoundError('Application not found');
        }

        const updatedApplication = await prisma.application.update({
            where: { id },
            data
        });

        return updatedApplication;
    }

    static async regenerateApiKey(id: string) {
        const application = await prisma.application.findUnique({
            where: { id }
        });

        if (!application) {
            throw new NotFoundError('Application not found');
        }

        const newApiKey = this.generateApiKey();

        const updatedApplication = await prisma.application.update({
            where: { id },
            data: { apiKey: newApiKey }
        });

        return updatedApplication;
    }

    static async toggleActive(id: string) {
        const application = await prisma.application.findUnique({
            where: { id }
        });

        if (!application) {
            throw new NotFoundError('Application not found');
        }

        const updatedApplication = await prisma.application.update({
            where: { id },
            data: { isActive: !application.isActive }
        });

        return updatedApplication;
    }

    static async deleteApplication(id: string, force: boolean = false) {
        const application = await prisma.application.findUnique({
            where: { id },
            include: {
                users: true
            }
        });

        if (!application) {
            throw new NotFoundError('Application not found');
        }

        if (application.users.length > 0 && !force) {
            throw new BadRequestError(
                `Cannot delete application with ${application.users.length} active user(s). Use force=true to confirm deletion.`
            );
        }

        await prisma.application.delete({
            where: { id }
        });

        return application;
    }

    static async getUsersByApp(appId: string) {
        const application = await prisma.application.findUnique({
            where: { id: appId },
            include: {
                users: {
                    include: {
                        user: {
                            select: {
                                id: true,
                                email: true,
                                emailVerified: true,
                                createdAt: true
                            }
                        }
                    }
                }
            }
        });
    
        if (!application) {
            throw new NotFoundError('Application not found');
        }
    
        return application.users;
    }
}

