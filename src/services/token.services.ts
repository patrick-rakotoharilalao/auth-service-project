import jwt from "jsonwebtoken";

const SECRET = "mon_secret_de_test";

export function generateToken(userId: string): string {
    return jwt.sign({ userId }, SECRET, { expiresIn: "1h" });
}

export function verifyToken(token: string): { userId: string } {
    return jwt.verify(token, SECRET) as { userId: string };
}