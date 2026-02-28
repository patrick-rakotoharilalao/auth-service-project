// mfa.routes.ts
import { Router } from "express";
import { body } from "express-validator";
import { disable2FA, setup2FA, verify2FA, verifyMfaLogin } from "@/controllers/mfa.controller";
import { authenticate } from "@/middlewares/auth.middleware";
import { verifyApplication } from "@/middlewares/verifyApplication.middleware";
import { checkUserAppAccess } from "@/middlewares/checkUserAppAccess.middeware";

const router = Router();

router.post('/2fa/setup', [authenticate, verifyApplication, checkUserAppAccess], setup2FA);
router.post('/2fa/verify', [authenticate, verifyApplication, checkUserAppAccess], verify2FA);
router.post('/2fa/verify-login', verifyApplication, verifyMfaLogin);
router.post('/2fa/disable', [
    authenticate,
    body('password').notEmpty().withMessage('Password is required'),
    verifyApplication
], disable2FA);

export default router;