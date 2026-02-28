// auth.routes.ts
import { Router } from "express";
import { body } from "express-validator";
import { forgotPassword, login, logout, refreshToken, register, resetPassword } from "@/controllers/auth.controller";
import { authenticate } from "@/middlewares/auth.middleware";
import { loginRegisterRateLimit } from "@/middlewares/rateLimit.middleware";
import { verifyApplication } from "@/middlewares/verifyApplication.middleware";
import { checkUserAppAccess } from "@/middlewares/checkUserAppAccess.middeware";

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
    verifyApplication
], register);

router.post('/login', [
    loginRegisterRateLimit,
    body('email').isEmail().withMessage('Invalid email'),
    body('password').notEmpty().withMessage('Password is required'),
    verifyApplication
], login);

router.post('/logout', [authenticate, verifyApplication, checkUserAppAccess], logout);

router.post('/forgot-password', [
    body('email').isEmail().withMessage('Invalid email'),
    verifyApplication
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
    verifyApplication
], resetPassword);

router.post('/refresh-token', [verifyApplication
], refreshToken);

export default router;