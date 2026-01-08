// app.ts
import express, { Request, Response } from 'express';
import prisma from './lib/prisma';
import 'dotenv/config';
const app = express();

app.use(express.json());

export default app;