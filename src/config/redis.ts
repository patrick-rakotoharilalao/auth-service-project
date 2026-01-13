import { createClient, RedisClientType } from 'redis';
import dotenv from 'dotenv';

dotenv.config();

export interface RedisConfig {
    host: string;
    port: number;
    password?: string;
    db?: number;
}

class RedisConnection {
    private static instance: RedisConnection;
    private client: RedisClientType;
    private isConnected: boolean = false;

    private constructor() {
        const config: RedisConfig = {
            host: process.env.REDIS_HOST || 'localhost',
            port: parseInt(process.env.REDIS_PORT || '6379'),
            password: process.env.REDIS_PASSWORD || undefined,
            db: parseInt(process.env.REDIS_DB || '0')
        };

        this.client = createClient({
            url: `redis://${config.host}:${config.port}`,
            password: config.password,
            database: config.db
        });

        this.setupEventListeners();
    }

    private setupEventListeners(): void {
        this.client.on('connect', () => {
            console.log('🔗 Redis connecting...');
        });

        this.client.on('ready', () => {
            this.isConnected = true;
            console.log('Redis connected successfully');
        });

        this.client.on('error', (error) => {
            console.error('Redis error:', error);
            this.isConnected = false;
        });

        this.client.on('end', () => {
            console.log('🔌 Redis disconnected');
            this.isConnected = false;
        });

        this.client.on('reconnecting', () => {
            console.log('🔄 Redis reconnecting...');
        });
    }

    public static getInstance(): RedisConnection {
        if (!RedisConnection.instance) {
            RedisConnection.instance = new RedisConnection();
        }
        return RedisConnection.instance;
    }

    public async connect(): Promise<void> {
        if (!this.isConnected) {
            try {
                await this.client.connect();
            } catch (error) {
                console.error('Failed to connect to Redis:', error);
                throw error;
            }
        }
    }

    public async disconnect(): Promise<void> {
        if (this.isConnected) {
            await this.client.quit();
            this.isConnected = false;
        }
    }

    public getClient(): RedisClientType {
        return this.client;
    }

    public isReady(): boolean {
        return this.isConnected;
    }
}

export const redisConnection = RedisConnection.getInstance();

(async () => {
    try {
        await redisConnection.connect();
    } catch (error) {
        console.error('Failed to auto-connect Redis:', error);
    }
})();