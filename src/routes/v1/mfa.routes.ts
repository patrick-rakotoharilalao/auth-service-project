// mfa.routes.ts
import { Router } from "express";
import { body } from "express-validator";
import { disable2FA, setup2FA, verify2FA, verifyMfaLogin } from "@/controllers/mfa.controller";
import { authenticate } from "@/middlewares/auth.middleware";
import { verifyApplication } from "@/middlewares/verifyApplication.middleware";
import { checkUserAppAccess } from "@/middlewares/checkUserAppAccess.middeware";

const router = Router();

/**
 * @swagger
 * /auth/2fa/setup:
 *   post:
 *     summary: Setup two-factor authentication
 *     tags: [Two-Factor Authentication]
 *     security:
 *       - ApiKeyAuth: []
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: 2FA setup initiated
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 secret:
 *                   type: string
 *                 qrCode:
 *                   type: string
 *                 backupCodes:
 *                   type: array
 *                   items:
 *                     type: string
 *       401:
 *         description: Unauthorized
 */
router.post('/2fa/setup', [authenticate, verifyApplication, checkUserAppAccess], setup2FA);

/**
 * @swagger
 * /auth/2fa/verify:
 *   post:
 *     summary: Verify and activate 2FA
 *     description: Verifies the TOTP code from Google Authenticator and enables 2FA for the user account
 *     tags: [Two-Factor Authentication]
 *     security:
 *       - ApiKeyAuth: []
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - code
 *             properties:
 *               code:
 *                 type: string
 *                 description: 6-digit TOTP code from Google Authenticator
 *                 example: "123456"
 *                 minLength: 6
 *                 maxLength: 6
 *     responses:
 *       200:
 *         description: 2FA activated successfully
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
 *                   example: Multi-factoring authentication enabled successfully
 *                 backupCodes:
 *                   type: array
 *                   description: 10 backup codes for account recovery (save these securely)
 *                   items:
 *                     type: string
 *                   example: ["A3B5-C7D9", "E1F2-G4H6", "I8J0-K2L4"]
 *       401:
 *         description: Invalid TOTP code or unauthorized
 *       403:
 *         description: Forbidden - No access to this application
 *       404:
 *         description: User not found
 */
router.post('/2fa/verify', [authenticate, verifyApplication, checkUserAppAccess], verify2FA);

/**
 * @swagger
 * /auth/2fa/verify-login:
 *   post:
 *     summary: Complete 2FA login (second step)
 *     description: Verifies the 2FA code and completes the login process after initial credentials validation
 *     tags: [Two-Factor Authentication]
 *     security:
 *       - ApiKeyAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - tempToken
 *               - code
 *             properties:
 *               tempToken:
 *                 type: string
 *                 description: Temporary token received from initial login attempt
 *                 example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *               code:
 *                 type: string
 *                 description: 6-digit TOTP code from Google Authenticator or 8-character backup code
 *                 example: "123456"
 *     responses:
 *       200:
 *         description: Login successful with 2FA verification
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
 *                   example: Login successful
 *                 data:
 *                   type: object
 *                   properties:
 *                     user:
 *                       type: object
 *                       properties:
 *                         userId:
 *                           type: string
 *                         email:
 *                           type: string
 *                     accessToken:
 *                       type: string
 *                     sessionId:
 *                       type: string
 *       400:
 *         description: Validation error
 *       401:
 *         description: Invalid code or temp token
 *       403:
 *         description: Forbidden - Invalid API key
 */
router.post('/2fa/verify-login', verifyApplication, verifyMfaLogin);

/**
 * @swagger
 * /auth/2fa/disable:
 *   post:
 *     summary: Disable 2FA for user account
 *     description: Disables two-factor authentication after password verification. Removes TOTP secret and backup codes.
 *     tags: [Two-Factor Authentication]
 *     security:
 *       - ApiKeyAuth: []
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - password
 *             properties:
 *               password:
 *                 type: string
 *                 format: password
 *                 description: Current account password for verification
 *                 example: SecurePass123!
 *     responses:
 *       200:
 *         description: 2FA disabled successfully
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
 *                   example: Multi-factoring authentication disabled successfully
 *       400:
 *         description: Validation error
 *       401:
 *         description: Unauthorized - Invalid password or token
 *       403:
 *         description: Forbidden - Invalid API key
 */
router.post('/2fa/disable', [
    authenticate,
    body('password').notEmpty().withMessage('Password is required'),
    verifyApplication
], disable2FA);

export default router;