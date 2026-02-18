import { Router } from "express";
import { body } from "express-validator";
import { disable2FA, setup2FA, verify2FA, verifyMfaLogin } from "@/controllers/mfa.controller";
import { authenticate } from "@/middlewares/auth.middleware";

const router = Router();

router.post('/2fa/setup', authenticate, setup2FA);
router.post('/2fa/verify', authenticate, verify2FA);
router.post('/2fa/verify-login', verifyMfaLogin);
router.post('/2fa/disable', [authenticate, body('password').notEmpty().withMessage('Password is required')], disable2FA);

export default router;