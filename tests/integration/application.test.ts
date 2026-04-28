import request from "supertest";
import app from "../../src/app";
import { ApplicationService } from "../../src/services/application.services";

// Avoid external side-effects while bootstrapping app
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

// Bypass auth/admin middlewares for application routes tests
jest.mock("@/middlewares/auth.middleware", () => ({
    authenticate: (req: any, _res: any, next: any) => {
        req.user = { userId: "admin-1", role: "admin" };
        req.accessToken = "fake-access-token";
        next();
    }
}));

jest.mock("@/middlewares/requireAdmin.middleware", () => ({
    requireAdmin: (_req: any, _res: any, next: any) => next()
}));

jest.mock("@/services/application.services", () => ({
    ApplicationService: {
        createApplication: jest.fn(),
        addUserToApp: jest.fn(),
        getAllApplications: jest.fn(),
        getApplicationById: jest.fn(),
        updateApplication: jest.fn(),
        regenerateApiKey: jest.fn(),
        toggleActive: jest.fn(),
        deleteApplication: jest.fn(),
        getUsersByApp: jest.fn(),
        removeUserFromApp: jest.fn()
    }
}));

describe("Application routes integration", () => {
    beforeEach(() => {
        jest.spyOn(console, "error").mockImplementation(() => { });
        jest.spyOn(console, "warn").mockImplementation(() => { });
        jest.clearAllMocks();
    });

    test("POST /api/v1/applications creates application", async () => {
        (ApplicationService.createApplication as jest.Mock).mockResolvedValue({
            id: "app-1",
            name: "My App",
            description: "Desc",
            apiKey: "app_secret_key_123",
            allowedOrigins: ["https://client.app"],
            webhookUrl: "https://client.app/webhooks",
            createdAt: new Date().toISOString()
        });
        (ApplicationService.addUserToApp as jest.Mock).mockResolvedValue({
            user: { email: "owner@test.com" }
        });

        const response = await request(app)
            .post("/api/v1/applications")
            .set("Authorization", "Bearer any-token")
            .send({
                name: "My App",
                description: "Desc",
                allowedOrigins: ["https://client.app"],
                webhookUrl: "https://client.app/webhooks"
            });

        expect(response.status).toBe(201);
        expect(response.body.success).toBe(true);
        expect(response.body.data.name).toBe("My App");
    });

    test("POST /api/v1/applications returns 422 on invalid payload", async () => {
        const response = await request(app)
            .post("/api/v1/applications")
            .set("Authorization", "Bearer any-token")
            .send({
                name: "",
                allowedOrigins: ["not-a-url"],
                webhookUrl: "invalid-url"
            });

        expect(response.status).toBe(422);
        expect(response.body.success).toBe(false);
    });

    test("GET /api/v1/applications returns all applications", async () => {
        (ApplicationService.getAllApplications as jest.Mock).mockResolvedValue([
            {
                id: "app-1",
                name: "App One",
                description: "A",
                apiKey: "app_key_one",
                allowedOrigins: ["https://one.app"],
                webhookUrl: "https://one.app/hook",
                isActive: true,
                createdAt: new Date().toISOString(),
                updatedAt: new Date().toISOString()
            }
        ]);

        const response = await request(app)
            .get("/api/v1/applications")
            .set("Authorization", "Bearer any-token");

        expect(response.status).toBe(200);
        expect(response.body.success).toBe(true);
        expect(response.body.data).toHaveLength(1);
    });

    test("GET /api/v1/applications/:id returns one application", async () => {
        (ApplicationService.getApplicationById as jest.Mock).mockResolvedValue({
            id: "app-1",
            name: "App One",
            description: "A",
            apiKey: "app_key_one",
            allowedOrigins: ["https://one.app"],
            webhookUrl: "https://one.app/hook",
            isActive: true,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        });

        const response = await request(app)
            .get("/api/v1/applications/app-1")
            .set("Authorization", "Bearer any-token");

        expect(response.status).toBe(200);
        expect(response.body.success).toBe(true);
        expect(response.body.data.id).toBe("app-1");
    });

    test("PATCH /api/v1/applications/:id updates application", async () => {
        (ApplicationService.updateApplication as jest.Mock).mockResolvedValue({
            id: "app-1",
            name: "Updated App",
            description: "Updated",
            apiKey: "app_key_one",
            allowedOrigins: ["https://updated.app"],
            webhookUrl: "https://updated.app/hook",
            isActive: true,
            updatedAt: new Date().toISOString()
        });

        const response = await request(app)
            .patch("/api/v1/applications/app-1")
            .set("Authorization", "Bearer any-token")
            .send({
                name: "Updated App",
                webhookUrl: "https://updated.app/hook"
            });

        expect(response.status).toBe(200);
        expect(response.body.success).toBe(true);
        expect(response.body.data.name).toBe("Updated App");
    });

    test("PATCH /api/v1/applications/:id returns 422 on invalid payload", async () => {
        const response = await request(app)
            .patch("/api/v1/applications/app-1")
            .set("Authorization", "Bearer any-token")
            .send({
                webhookUrl: "not-a-url"
            });

        expect(response.status).toBe(422);
        expect(response.body.success).toBe(false);
    });

    test("POST /api/v1/applications/:id/regenerate-key regenerates key", async () => {
        (ApplicationService.regenerateApiKey as jest.Mock).mockResolvedValue({
            id: "app-1",
            name: "App One",
            apiKey: "app_new_key_456",
            updatedAt: new Date().toISOString()
        });

        const response = await request(app)
            .post("/api/v1/applications/app-1/regenerate-key")
            .set("Authorization", "Bearer any-token");

        expect(response.status).toBe(200);
        expect(response.body.success).toBe(true);
        expect(response.body.data.apiKey).toBe("app_new_key_456");
    });

    test("PATCH /api/v1/applications/:id/toggle toggles active flag", async () => {
        (ApplicationService.toggleActive as jest.Mock).mockResolvedValue({
            id: "app-1",
            name: "App One",
            isActive: false,
            updatedAt: new Date().toISOString()
        });

        const response = await request(app)
            .patch("/api/v1/applications/app-1/toggle")
            .set("Authorization", "Bearer any-token");

        expect(response.status).toBe(200);
        expect(response.body.success).toBe(true);
        expect(response.body.data.isActive).toBe(false);
    });

    test("DELETE /api/v1/applications/:id deletes an application", async () => {
        (ApplicationService.deleteApplication as jest.Mock).mockResolvedValue({
            id: "app-1",
            name: "App One",
            users: []
        });

        const response = await request(app)
            .delete("/api/v1/applications/app-1")
            .set("Authorization", "Bearer any-token");

        expect(response.status).toBe(200);
        expect(response.body.success).toBe(true);
        expect(response.body.data.id).toBe("app-1");
    });

    test("GET /api/v1/applications/:id/users returns application users", async () => {
        (ApplicationService.getUsersByApp as jest.Mock).mockResolvedValue([
            {
                role: "admin",
                user: {
                    id: "user-1",
                    email: "user1@test.com",
                    emailVerified: true,
                    createdAt: new Date().toISOString()
                }
            }
        ]);

        const response = await request(app)
            .get("/api/v1/applications/app-1/users")
            .set("Authorization", "Bearer any-token");

        expect(response.status).toBe(200);
        expect(response.body.success).toBe(true);
        expect(response.body.data).toHaveLength(1);
    });

    test("POST /api/v1/applications/:id/users adds user to application", async () => {
        (ApplicationService.addUserToApp as jest.Mock).mockResolvedValue({
            userId: "user-2",
            applicationId: "app-1",
            role: "user",
            addedAt: new Date().toISOString(),
            user: { email: "user2@test.com" }
        });

        const response = await request(app)
            .post("/api/v1/applications/app-1/users")
            .set("Authorization", "Bearer any-token")
            .send({ userId: "user-2", role: "user" });

        expect(response.status).toBe(201);
        expect(response.body.success).toBe(true);
        expect(response.body.data.userId).toBe("user-2");
    });

    test("POST /api/v1/applications/:id/users returns 422 when userId is missing", async () => {
        const response = await request(app)
            .post("/api/v1/applications/app-1/users")
            .set("Authorization", "Bearer any-token")
            .send({ role: "user" });

        expect(response.status).toBe(422);
        expect(response.body.success).toBe(false);
    });

    test("DELETE /api/v1/applications/:id/users/:userId removes user from app", async () => {
        (ApplicationService.removeUserFromApp as jest.Mock).mockResolvedValue({
            userId: "user-1",
            applicationId: "app-1",
            user: { email: "user1@test.com" }
        });

        const response = await request(app)
            .delete("/api/v1/applications/app-1/users/user-1")
            .set("Authorization", "Bearer any-token");

        expect(response.status).toBe(200);
        expect(response.body.success).toBe(true);
        expect(response.body.data.userId).toBe("user-1");
    });
});
