import { PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import { envConfig } from '../config/env.config';

const adapter = new PrismaPg({
  host: envConfig.dbConfig.host,
  port: envConfig.dbConfig.port,
  user: envConfig.dbConfig.user,
  password: envConfig.dbConfig.password,
  database: envConfig.dbConfig.database,
});

const prisma = new PrismaClient({ adapter });

export default prisma;

