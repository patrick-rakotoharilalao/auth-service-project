// app.ts
import express, { Request, Response } from 'express';
import authRoutes from './routes/auth.routes';
import prisma from './lib/prisma';
import { redisService } from './services/redis.services';
const app = express();
import cookieParser from 'cookie-parser';
import cors from 'cors';

app.use(express.json());

app.use(cookieParser());

app.use(cors({
    origin: 'http://localhost:3000',
    credentials: true
}));

app.use('/api/auth', authRoutes);

app.get('/api/health', async (req: Request, res: Response) => {
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

export default app;