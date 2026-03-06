// auth.routes.ts
import { Router } from "express";
import { body } from "express-validator";
import { forgotPassword, login, logout, refreshToken, register, resetPassword } from "@/controllers/auth.controller";
import { authenticate } from "@/middlewares/auth.middleware";
import { loginRegisterRateLimit } from "@/middlewares/rateLimit.middleware";
import { verifyApplication } from "@/middlewares/verifyApplication.middleware";
import { checkUserAppAccess } from "@/middlewares/checkUserAppAccess.middeware";

const router = Router();
/**
 * @swagger
 * /auth/register:
 *   post:
 *     summary: Register a new user
 *     tags: [Authentication]
 *     security:
 *       - ApiKeyAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: user@example.com
 *               password:
 *                 type: string
 *                 format: password
 *                 example: SecurePass123!
 *     responses:
 *       201:
 *         description: User registered successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: User registered successfully
 *       422:
 *         description: Validation error
 *       409:
 *         description: User already exists
 */
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

/**
 * @swagger
 * /auth/login:
 *   post:
 *     summary: Login with email and password
 *     tags: [Authentication]
 *     security:
 *       - ApiKeyAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 example: user@example.com
 *               password:
 *                 type: string
 *                 example: SecurePass123!
 *     responses:
 *       200:
 *         description: Login successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 accessToken:
 *                   type: string
 *                 refreshToken:
 *                   type: string
 *                 requiresMfa:
 *                   type: boolean
 *                 tempToken:
 *                   type: string
 *       401:
 *         description: Invalid credentials
 */
router.post('/login', [
    loginRegisterRateLimit,
    body('email').isEmail().withMessage('Invalid email'),
    body('password').notEmpty().withMessage('Password is required'),
    verifyApplication
], login);

/**
 * @swagger
 * /auth/logout:
 *   post:
 *     summary: Logout user and revoke session
 *     description: Blacklists access and refresh tokens, revokes session in database, and clears cookies
 *     tags: [Authentication]
 *     security:
 *       - ApiKeyAuth: []
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Logout successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: Logout successful
 *       401:
 *         description: Unauthorized - Invalid or missing token
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 message:
 *                   type: string
 *                   example: Invalid access token
 *       403:
 *         description: Forbidden - No access to this application
 */
router.post('/logout', [authenticate, verifyApplication, checkUserAppAccess], logout);

/**
 * @swagger
 * /auth/forgot-password:
 *   post:
 *     summary: Request password reset
 *     description: Sends a password reset email if the account exists (generic response for security)
 *     tags: [Authentication]
 *     security:
 *       - ApiKeyAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: user@example.com
 *     responses:
 *       200:
 *         description: Password reset email sent (if account exists)
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: If an account with that email exists, we have sent a password reset link.
 *       400:
 *         description: Validation error
 *       403:
 *         description: Forbidden - Invalid API key or origin not allowed
 */
router.post('/forgot-password', [
    body('email').isEmail().withMessage('Invalid email'),
    verifyApplication
], forgotPassword);

/**
 * @swagger
 * /auth/reset-password:
 *   post:
 *     summary: Reset password with token
 *     description: Resets user password using the token received via email
 *     tags: [Authentication]
 *     security:
 *       - ApiKeyAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - token
 *               - newPassword
 *             properties:
 *               token:
 *                 type: string
 *                 description: Password reset token from email
 *                 example: a1b2c3d4e5f6g7h8i9j0
 *               newPassword:
 *                 type: string
 *                 format: password
 *                 description: Must be at least 8 characters with uppercase, lowercase, number, and special character
 *                 example: NewSecure123!
 *     responses:
 *       200:
 *         description: Password reset successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: Password changed successfully
 *       400:
 *         description: Validation error or invalid token
 *       403:
 *         description: Forbidden - Invalid API key
 *       410:
 *         description: Token expired
 */
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

/**
 * @swagger
 * /auth/refresh-token:
 *   post:
 *     summary: Refresh access token
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - refreshToken
 *             properties:
 *               refreshToken:
 *                 type: string
 *     responses:
 *       200:
 *         description: Token refreshed
 *       401:
 *         description: Invalid refresh token
 */
router.post('/refresh-token', [verifyApplication
], refreshToken);

export default router;