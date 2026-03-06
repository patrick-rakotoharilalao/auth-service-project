// src/routes/v1/index.ts
import { Router } from 'express';
import authRoutes from './auth.routes';
import oauthRoutes from './oauth.routes';
import mfaRoutes from './mfa.routes';
import applicationRoutes from './application.routes';

const v1Router = Router();

v1Router.use('/auth', authRoutes);
v1Router.use('/auth', oauthRoutes);
v1Router.use('/auth', mfaRoutes);
v1Router.use('/applications', applicationRoutes);

export default v1Router;