import { User } from "@/generated/prisma/client";
import prisma from "@/lib/prisma";
import bcrypt from 'bcrypt';
import { UnauthorizedError } from "@/errors";

export async function verifyCredentials(
    email: string,
    password: string | null,
    loginMethod: 'credentials' | 'oauth' = 'credentials'
): Promise<User> {

    const emailNormalized = email.toLowerCase();
    // Attempt to find user by email
    const user = await prisma.user.findUnique({
        where: { emailNormalized: emailNormalized }
    });


    if (!user) {
        await bcrypt.compare('$2b$10$fakehashforconstanttimeleft', '$2b$10$fakehashforconstanttimeright'); // Hash factice
        throw new UnauthorizedError('Invalid email or password')
    }

    if (loginMethod === 'oauth') {
        return user;
    }

    // Compare hashed password
    const isMatch = await bcrypt.compare(password!, user.passwordHash!);

    if (!isMatch) {
        throw new UnauthorizedError('Invalid email or password')
    }

    return user;
}