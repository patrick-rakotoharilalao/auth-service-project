import request from "supertest";
import jwt from "jsonwebtoken";
import app from "../../src/app";
import prisma from "../../src/lib/prisma";
import { AuthService } from "../../src/services/auth.services";
import { redisService } from "../../src/services/redis.services";

// Prevent external service side-effects during app bootstrap
jest.mock("../../src/services/email.service", () => ({
    EmailService: {
        initialize: jest.fn(),
        verifyConnection: jest.fn().mockResolvedValue(true)
    }
}));

jest.mock("../../src/services/redis.services", () => ({
    redisService: {
        ping: jest.fn().mockResolvedValue("PONG"),
        get: jest.fn().mockResolvedValue(null)
    }
}));

// Mock 1 - Prisma
jest.mock('@/lib/prisma', () => ({
    __esModule: true,
    default: {
        application: {
            findUnique: jest.fn()
        },
        userAppAccess: {
            findUnique: jest.fn()
        }
    }
}));

// Mock 2 - AuthService
jest.mock('@/services/auth.services');

describe("POST /api/v1/auth/login", () => {

    beforeEach(() => {
        jest.spyOn(console, 'error').mockImplementation(() => { });
        jest.spyOn(console, 'warn').mockImplementation(() => { });

        jest.clearAllMocks();

        // Mock application returned by Prisma
        (prisma.application.findUnique as jest.Mock).mockResolvedValue({
            id: "app-1",
            apiKey: "test-api-key",
            isActive: true,
            allowedOrigins: []
        });
        (prisma.userAppAccess.findUnique as jest.Mock).mockResolvedValue({
            userId: "user-1",
            applicationId: "app-1"
        });
        (redisService.get as jest.Mock).mockResolvedValue(null);

        // Mock successful result from AuthService.loginUser
        (AuthService.loginUser as jest.Mock).mockResolvedValue({
            requiresMfa: false,
            accessToken: "fake-access-token",
            refreshToken: "fake-refresh-token",
            user: { id: "user-1", email: "test@example.com" },
            session: { id: "session-1" }
        });
    });

    test("successful login returns 200 and accessToken", async () => {
        const response = await request(app)
            .post("/api/v1/auth/login")
            .set("x-api-key", "test-api-key")
            .send({ email: "test@example.com", password: "Password123!" });

        expect(response.status).toBe(200);
        expect(response.body.success).toBe(true);
        expect(response.body.data.accessToken).toBe("fake-access-token");
    });

    test("invalid email returns 422", async () => {
        const response = await request(app)
            .post("/api/v1/auth/login")
            .set("x-api-key", "test-api-key")
            .send({ email: "testexample.com", password: "Password123!" });

        expect(response.status).toBe(422);
        expect(response.body.success).toBe(false);
    });

    test("missing API key returns 401", async () => {
        const response = await request(app)
            .post("/api/v1/auth/login")
            .send({ email: "test@example.com", password: "Password123!" });

        expect(response.status).toBe(401);
        expect(response.body.success).toBe(false);
    });

    test("requires mfa return 200", async () => {
        (AuthService.loginUser as jest.Mock).mockResolvedValue({
            requiresMfa: true,
            tempToken: "fake-temp-token",
            user: { id: "user-1", email: "test@example.com" },
        });

        const response = await request(app)
            .post("/api/v1/auth/login")
            .set("x-api-key", "test-api-key")
            .send({ email: "test@example.com", password: "Password123!" });

        expect(response.status).toBe(200);
        expect(response.body.success).toBe(true);
        expect(response.body.data.tempToken).toBe("fake-temp-token");
    });
});

describe("POST /api/v1/auth/register", () => {

    beforeEach(() => {
        jest.spyOn(console, 'error').mockImplementation(() => { });
        jest.spyOn(console, 'warn').mockImplementation(() => { });
        jest.clearAllMocks();

        (prisma.application.findUnique as jest.Mock).mockResolvedValue({
            id: "app-1",
            apiKey: "test-api-key",
            isActive: true,
            allowedOrigins: []
        });
        (prisma.userAppAccess.findUnique as jest.Mock).mockResolvedValue({
            userId: "user-1",
            applicationId: "app-1"
        });
        (redisService.get as jest.Mock).mockResolvedValue(null);

        (AuthService.createUser as jest.Mock).mockResolvedValue({
            email: 'user-1@example.com'
        });

    });

    test("successfull register returns 201", async () => {
        const response = await request(app)
            .post("/api/v1/auth/register")
            .set("x-api-key", "test-api-key")
            .send({ email: "user-1@gmail.com", password: "Password123!" });

        expect(response.status).toBe(201);
        expect(response.body.success).toBe(true);
        expect(response.body.message).toBe("User registered with email: user-1@gmail.com");
    });

    test("invalid email returns 422", async () => {
        const response = await request(app)
            .post("/api/v1/auth/register")
            .set("x-api-key", "test-api-key")
            .send({ email: "user-1gmail.com", password: "Password123!" });

        expect(response.status).toBe(422);
        expect(response.body.success).toBe(false);
    });

    test("missing API Key returns 401", async () => {
        const response = await request(app)
            .post("/api/v1/auth/register")
            .send({ email: "user-1gmail.com", password: "Password123!" });

        expect(response.status).toBe(401);
        expect(response.body.success).toBe(false);
    });
});

describe("POST /api/v1/auth/forgot-password", () => {
    beforeEach(() => {
        jest.spyOn(console, 'error').mockImplementation(() => { });
        jest.spyOn(console, 'warn').mockImplementation(() => { });
        jest.clearAllMocks();

        (prisma.application.findUnique as jest.Mock).mockResolvedValue({
            id: "app-1",
            apiKey: "test-api-key",
            isActive: true,
            allowedOrigins: []
        });
        (AuthService.forgotUserPassword as jest.Mock).mockResolvedValue(undefined);
    });

    test("forgot password returns 200 with generic message", async () => {
        const response = await request(app)
            .post("/api/v1/auth/forgot-password")
            .set("x-api-key", "test-api-key")
            .send({ email: "test@example.com" });

        expect(response.status).toBe(200);
        expect(response.body.success).toBe(true);
        expect(response.body.message).toContain("If an account with that email exists");
    });

    test("forgot password with invalid email returns 422", async () => {
        const response = await request(app)
            .post("/api/v1/auth/forgot-password")
            .set("x-api-key", "test-api-key")
            .send({ email: "testexample.com" });

        expect(response.status).toBe(422);
        expect(response.body.success).toBe(false);
    });
});

describe("POST /api/v1/auth/reset-password", () => {
    beforeEach(() => {
        jest.spyOn(console, 'error').mockImplementation(() => { });
        jest.spyOn(console, 'warn').mockImplementation(() => { });
        jest.clearAllMocks();

        (prisma.application.findUnique as jest.Mock).mockResolvedValue({
            id: "app-1",
            apiKey: "test-api-key",
            isActive: true,
            allowedOrigins: []
        });
        (AuthService.resetUserPassword as jest.Mock).mockResolvedValue({
            userId: "user-1"
        });
    });

    test("reset password returns 200", async () => {
        const response = await request(app)
            .post("/api/v1/auth/reset-password")
            .set("x-api-key", "test-api-key")
            .send({ token: "reset-token-123", newPassword: "NewPassword123!" });

        expect(response.status).toBe(200);
        expect(response.body.success).toBe(true);
        expect(response.body.message).toBe("Password changed successfully");
    });

    test("reset password with missing token returns 422", async () => {
        const response = await request(app)
            .post("/api/v1/auth/reset-password")
            .set("x-api-key", "test-api-key")
            .send({ newPassword: "NewPassword123!" });

        expect(response.status).toBe(422);
        expect(response.body.success).toBe(false);
    });
});

describe("POST /api/v1/auth/refresh-token", () => {
    beforeEach(() => {
        jest.spyOn(console, 'error').mockImplementation(() => { });
        jest.spyOn(console, 'warn').mockImplementation(() => { });
        jest.clearAllMocks();

        (prisma.application.findUnique as jest.Mock).mockResolvedValue({
            id: "app-1",
            apiKey: "test-api-key",
            isActive: true,
            allowedOrigins: []
        });
        (AuthService.refreshUserToken as jest.Mock).mockResolvedValue("new-access-token");
    });

    test("refresh token returns 200 with a new access token", async () => {
        const response = await request(app)
            .post("/api/v1/auth/refresh-token")
            .set("x-api-key", "test-api-key")
            .set("Cookie", ["refreshToken=refresh-token-123", "sessionId=session-1"]);

        expect(response.status).toBe(200);
        expect(response.body.success).toBe(true);
        expect(response.body.accessToken).toBe("new-access-token");
    });

    test("refresh token without cookie returns 400", async () => {
        const response = await request(app)
            .post("/api/v1/auth/refresh-token")
            .set("x-api-key", "test-api-key");

        expect(response.status).toBe(400);
        expect(response.body.success).toBe(false);
    });
});

describe("POST /api/v1/auth/logout", () => {
    beforeEach(() => {
        jest.spyOn(console, 'error').mockImplementation(() => { });
        jest.spyOn(console, 'warn').mockImplementation(() => { });
        jest.clearAllMocks();

        (prisma.application.findUnique as jest.Mock).mockResolvedValue({
            id: "app-1",
            apiKey: "test-api-key",
            isActive: true,
            allowedOrigins: []
        });
        (prisma.userAppAccess.findUnique as jest.Mock).mockResolvedValue({
            userId: "user-1",
            applicationId: "app-1"
        });
        (redisService.get as jest.Mock).mockResolvedValue(null);
        (AuthService.revokingData as jest.Mock).mockResolvedValue(undefined);
    });

    test("logout returns 200 when access and refresh tokens are provided", async () => {
        const accessToken = jwt.sign(
            { userId: "user-1", sessionId: "session-1", id: "user-1" },
            process.env.JWT_SECRET as string
        );

        const response = await request(app)
            .post("/api/v1/auth/logout")
            .set("x-api-key", "test-api-key")
            .set("Authorization", `Bearer ${accessToken}`)
            .set("Cookie", ["refreshToken=refresh-token-123"]);

        expect(response.status).toBe(200);
        expect(response.body.success).toBe(true);
        expect(response.body.message).toBe("Logout successful");
    });

    test("logout without refresh token returns 401", async () => {
        const accessToken = jwt.sign(
            { userId: "user-1", sessionId: "session-1", id: "user-1" },
            process.env.JWT_SECRET as string
        );

        const response = await request(app)
            .post("/api/v1/auth/logout")
            .set("x-api-key", "test-api-key")
            .set("Authorization", `Bearer ${accessToken}`);

        expect(response.status).toBe(401);
        expect(response.body.success).toBe(false);
    });
});