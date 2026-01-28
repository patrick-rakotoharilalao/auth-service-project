import { redisConnection } from '../config/redis';

export class RedisService {
    private client = redisConnection.getClient();
    private defaultTTL: number = parseInt(process.env.REDIS_TTL || '3600') * 24 * 60 * 60; // in seconds

    // basic methods
    async set(key: string, value: any, ttl?: number): Promise<void> {
        try {
            const stringValue = typeof value === 'string' ? value : JSON.stringify(value);
            const expireTime = ttl || this.defaultTTL;

            await this.client.set(key, stringValue);
            if (expireTime > 0) {
                await this.client.expire(key, expireTime);
            }
        } catch (error) {
            console.error(`Error setting key ${key}:`, error);
            throw error;
        }
    }

    async get<T>(key: string): Promise<T | null> {
        try {
            const value = await this.client.get(key);
            if (!value) return null;

            try {
                return JSON.parse(value) as T;
            } catch {
                return value as unknown as T;
            }
        } catch (error) {
            console.error(`Error getting key ${key}:`, error);
            throw error;
        }
    }

    async del(key: string): Promise<void> {
        try {
            await this.client.del(key);
        } catch (error) {
            console.error(`Error deleting key ${key}:`, error);
            throw error;
        }
    }

    async exists(key: string): Promise<boolean> {
        try {
            const result = await this.client.exists(key);
            return result === 1;
        } catch (error) {
            console.error(`Error checking existence of key ${key}:`, error);
            throw error;
        }
    }

    async incr(key: string): Promise<number> {
        try {
            return await this.client.incr(key);
        } catch (error) {
            console.error(`Error incrementing key ${key}:`, error);
            throw error;
        }
    }

    async decr(key: string): Promise<number> {
        try {
            return await this.client.decr(key);
        } catch (error) {
            console.error(`Error decrementing key ${key}:`, error);
            throw error;
        }
    }

    // Méthodes avancées
    // async setWithNX(key: string, value: any, ttl?: number): Promise<boolean> {
    //     try {
    //         const stringValue = typeof value === 'string' ? value : JSON.stringify(value);
    //         const expireTime = ttl || this.defaultTTL;

    //         const result = await this.client.setNX(key, stringValue);
    //         if (result && expireTime > 0) {
    //             await this.client.expire(key, expireTime);
    //         }
    //         return result;
    //     } catch (error) {
    //         console.error(`Error setting NX key ${key}:`, error);
    //         throw error;
    //     }
    // }

    async hSet(key: string, field: string, value: any): Promise<void> {
        try {
            const stringValue = typeof value === 'string' ? value : JSON.stringify(value);
            await this.client.hSet(key, field, stringValue);
        } catch (error) {
            console.error(`Error hSet key ${key}:`, error);
            throw error;
        }
    }

    async hGet<T>(key: string, field: string): Promise<T | null> {
        try {
            const value = await this.client.hGet(key, field);
            if (!value) return null;

            try {
                return JSON.parse(value) as T;
            } catch {
                return value as unknown as T;
            }
        } catch (error) {
            console.error(`Error hGet key ${key}:`, error);
            throw error;
        }
    }

    async getAllKeys(pattern: string = '*'): Promise<string[]> {
        try {
            return await this.client.keys(pattern);
        } catch (error) {
            console.error('Error getting all keys:', error);
            throw error;
        }
    }

    async flushDb(): Promise<void> {
        try {
            await this.client.flushDb();
        } catch (error) {
            console.error('Error flushing database:', error);
            throw error;
        }
    }

    async ping(): Promise<string> {
        try {
            return await this.client.ping();
        } catch (error) {
            console.error('Error pinging Redis:', error);
            throw error;
        }
    }

    async getStats(): Promise<any> {
        try {
            const info = await this.client.info();
            const keys = await this.client.dbSize();

            return {
                connected: redisConnection.isReady(),
                keys,
                info: info.split('\r\n').slice(0, 20) // Premières 20 lignes
            };
        } catch (error) {
            console.error('Error getting Redis stats:', error);
            throw error;
        }
    }

    async ttl<T>(key: string): Promise<number> {
        try {
            const value = await this.client.ttl(key);
            return value;

        } catch (error) {
            console.error(`Error getting ttl for key ${key}:`, error);
            throw error;
        }
    }
}

export const redisService = new RedisService();