// auth.routes.ts
import { Router } from "express";
import { body } from "express-validator";
import { forgotPassword, login, logout, refreshToken, register, resetPassword, setup2FA } from "../controllers/auth.controller";
import { authenticate } from "../middlewares/auth.middleware";
import { loginRegisterRateLimit } from "../middlewares/rateLimit.middleware";

const router = Router();

router.post('/register', [
    loginRegisterRateLimit,
    body('email').isEmail().withMessage('Invalid email'),
    body('password')
        .isLength({ min: 8 }).withMessage('Password must be at least 6 characters long')
        .matches(/[0-9]/).withMessage('Password must contain a number')
        .matches(/[A-Z]/).withMessage('Password must contain an uppercase letter')
        .matches(/[a-z]/).withMessage('Password must contain a lowercase letter')
        .matches(/[@$!%*?&-_]/).withMessage('Password must contain a special character'),
], register);

router.post('/login', [
    loginRegisterRateLimit,
    body('email').isEmail().withMessage('Invalid email'),
    body('password').notEmpty().withMessage('Password is required'),
    // rateLimiter({ windowMs: 15 * 60 * 1000, max: 5 }) // to implement later
], login);

router.post('/logout', authenticate, logout);

router.post('/forgot-password', [
    body('email').isEmail().withMessage('Invalid email')
], forgotPassword);

router.post('/reset-password', [
    body('token').notEmpty().withMessage('Token is required'),
    body('newPassword')
        .notEmpty().withMessage('Password is required')
        .isLength({ min: 8 }).withMessage('Password must be at least 6 characters long')
        .matches(/[0-9]/).withMessage('Password must contain a number')
        .matches(/[A-Z]/).withMessage('Password must contain an uppercase letter')
        .matches(/[a-z]/).withMessage('Password must contain a lowercase letter')
        .matches(/[@$!%*?&-_]/).withMessage('Password must contain a special character'),
], resetPassword);

router.post('/refresh-token', [
], refreshToken);

router.post('/2fa/setup', authenticate, setup2FA);



export default router;