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
}