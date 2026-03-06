// app.ts
import cookieParser from 'cookie-parser';
import cors from 'cors';
import express, { Request, Response } from 'express';
import passport from './config/passport.config';
import prisma from './lib/prisma';
import { errorHandler } from './middlewares/errorHandler';
import { otherRateLimit } from './middlewares/rateLimit.middleware';
import authRoutes from './routes/auth.routes';
import oauthRoutes from './routes/oauth.routes';
import mfaRoutes from './routes/mfa.routes';
import applicationRoutes from './routes/application.routes';
import { EmailService } from './services/email.service';
import { redisService } from './services/redis.services';
import swaggerUi from 'swagger-ui-express';
import { swaggerSpec } from './config/swagger.config';
const app = express();
import v1Router from './routes/v1';
// Initialize email service
try {
    EmailService.initialize();
    EmailService.verifyConnection();
    console.log('Email service initialization done');
} catch (error) {
    console.warn('Email service initialization failed. Email features will not work:', error);
}

app.set('trust proxy', 1);

app.use(express.json());

app.use(cookieParser());

app.use(cors({
    origin: 'http://localhost:3000',
    credentials: true
}));

app.use(otherRateLimit);

// Swagger Documentation
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec, {
    customCss: '.swagger-ui .topbar { display: none }',
    customSiteTitle: 'Auth as a Service - API Docs',
}));

// JSON spec endpoint
app.get('/api-docs.json', (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.send(swaggerSpec);
});

app.get("/", (req, res) => {
    res.send("Welcome to the Auth Service!");
});

// Passport initialization
app.use(passport.initialize()); // Configure Passport

app.use('/api/v1', v1Router);

app.get('/health', async (req: Request, res: Response) => {
    try {
        console.log(res.status);
        await prisma.$queryRaw`SELECT 1`;
        const pong = await redisService.ping();
        console.log('Redis response: ', pong);
        res.status(200).send('Service is healthy');
    } catch (error) {
        console.log('Health check failed:', error);
        res.status(500).send('Service is unhealthy: ');
    }
});

app.use(errorHandler);

export default app;