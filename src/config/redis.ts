import { createClient, RedisClientType } from 'redis';
import { envConfig } from './env.config';

export interface RedisConfig {
    host: string;
    port: number;
    password?: string;
    db?: number;
    url?: string;
}

class RedisConnection {
    private static instance: RedisConnection;
    private client: RedisClientType;
    private isConnected: boolean = false;

    private constructor() {
        const config: RedisConfig = {
            host: envConfig.redisConfig.host,
            port: envConfig.redisConfig.port,
            password: envConfig.redisConfig.password,
            db: envConfig.redisConfig.db,
            url: (envConfig.redisConfig as any).redisUrl 
        };
        this.client = createClient({
            url: config.url || `redis://${config.password ? `:${config.password}@` : ''}${config.host}:${config.port}`,
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
            console.log('✅ Redis connected successfully');
        });

        this.client.on('error', (error) => {
            console.error('❌ Redis error:', error);
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