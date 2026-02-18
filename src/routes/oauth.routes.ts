import { Router, Request, Response } from 'express';
import passport from '@/config/passport.config';
import { googleAuth, googleCallback } from '@/controllers/oauth.controller';

const router = Router();

// Start Google Authentication
router.get('/google',
    googleAuth
);

// Google Callback
router.get(
    '/google/callback',
    passport.authenticate('google', {
        failureRedirect: '/login?error=google_auth_failed',
        session: false
    }),
    googleCallback
);

export default router;