// oauth.routes.ts
import { Router, Request, Response } from 'express';
import passport from '@/config/passport.config';
import { googleAuth, googleCallback } from '@/controllers/oauth.controller';
import { verifyApplication } from '@/middlewares/verifyApplication.middleware';
import { extractApiKeyFromState } from '@/middlewares/apiKey.middleware';

const router = Router();

// Start Google Authentication
router.get('/google',
    verifyApplication,
    googleAuth
);

// Google Callback
router.get(
    '/google/callback',
    [
        extractApiKeyFromState,
        verifyApplication,
        passport.authenticate('google', {
            failureRedirect: '/login?error=google_auth_failed',
            session: false
        })
    ],
    googleCallback
);

export default router;