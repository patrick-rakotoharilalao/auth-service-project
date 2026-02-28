import bcrypt from 'bcrypt';
import crypto from 'crypto';
import prisma from '../lib/prisma';
import { Role } from '../generated/prisma/enums';

const SEED_DATA = {
    admin: {
        email: 'admin@auth.com',
        password: 'Admin.auth',
    },
    application: {
        name: 'Default Application',
        description: 'Default application for development and testing',
        allowedOrigins: ['http://localhost:3001', 'http://localhost:3000'],
    },
};

async function seedAdmin() {
    let admin = await prisma.user.findUnique({
        where: { emailNormalized: SEED_DATA.admin.email }
    });

    if (admin) {
        console.log('⚠️  Admin user already exists:', admin.email);
        return admin;
    }

    const passwordHash = await bcrypt.hash(SEED_DATA.admin.password, 10);
    admin = await prisma.user.create({
        data: {
            email: SEED_DATA.admin.email,
            emailNormalized: SEED_DATA.admin.email,
            passwordHash,
            emailVerified: true,
            mfaEnabled: false,
            role: Role.ADMIN,
        },
    });

    console.log('✅ Admin user created:', admin.email);
    return admin;
}

async function seedApplication() {
    let app = await prisma.application.findFirst({
        where: { name: SEED_DATA.application.name }
    });

    if (app) {
        console.log('⚠️  Application already exists:', app.name);
        return app;
    }

    const apiKey = `app_${crypto.randomBytes(32).toString('hex')}`;
    app = await prisma.application.create({
        data: {
            name: SEED_DATA.application.name,
            description: SEED_DATA.application.description,
            apiKey,
            allowedOrigins: SEED_DATA.application.allowedOrigins,
            webhookUrl: null,
            isActive: true,
        },
    });

    console.log('✅ Application created:', app.name);
    return app;
}

async function grantAdminAccess(adminId: string, appId: string) {
    const existingAccess = await prisma.userAppAccess.findUnique({
        where: {
            userId_applicationId: {
                userId: adminId,
                applicationId: appId,
            },
        },
    });

    if (existingAccess) {
        console.log('⚠️  Admin already has access to the application');
        return existingAccess;
    }

    const access = await prisma.userAppAccess.create({
        data: {
            userId: adminId,
            applicationId: appId,
            role: 'owner',
        },
    });

    console.log('✅ Admin access granted with owner role');
    return access;
}

async function main() {
    console.log('🌱 Starting database seed...\n');

    try {
        const admin = await seedAdmin();
        const app = await seedApplication();
        await grantAdminAccess(admin.id, app.id);

        console.log('\n' + '='.repeat(60));
        console.log('🎉 Seed completed successfully!');
        console.log('='.repeat(60));
        console.log('\n📋 Default Credentials:');
        console.log('   Email:    ', admin.email);
        console.log('   Password: ', SEED_DATA.admin.password);
        console.log('\n🔑 Application Details:');
        console.log('   Name:     ', app.name);
        console.log('   API Key:  ', app.apiKey);
        console.log('='.repeat(60) + '\n');

    } catch (error) {
        console.error('\n❌ Seed failed:', error);
        throw error;
    }
}

main()
    .catch((error) => {
        console.error('Fatal error during seed:', error);
        process.exit(1);
    })
    .finally(async () => {
        await prisma.$disconnect();
    });