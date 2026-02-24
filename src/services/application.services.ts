import { NotFoundError } from "@/errors";
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
}

