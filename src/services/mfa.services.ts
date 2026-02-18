import { verifyCredentials } from "@/utils/auth.utils";
import prisma from "@/lib/prisma";

export class MfaService {
    static async disable2Fa(email: string, password: string) {
        const user = await verifyCredentials(email, password);
        // delete the TOTP code
        await prisma.user.update({
            where: {
                emailNormalized: email.toLowerCase()
            },
            data: {
                mfaEnabled: false,
                mfaSecret: null
            }
        });

        // delete all backup_codes for this user
        await prisma.backupCode.deleteMany({
            where: {
                userId: user.id
            },
        });
    }
}