// auth.routes.ts
import { body } from "express-validator";
import { login, register } from "../controllers/auth.controller";
import { Router } from "express";

const router = Router();

router.post("/register", [
    body('email').isEmail().withMessage('Invalid email'),
    body('password')
        .isLength({ min: 8 }).withMessage('Password must be at least 6 characters long')
        .matches(/[0-9]/).withMessage('Password must contain a number')
        .matches(/[A-Z]/).withMessage('Password must contain an uppercase letter')
        .matches(/[a-z]/).withMessage('Password must contain a lowercase letter')
        .matches(/[@$!%*?&-_]/).withMessage('Password must contain a special character'),
], register);

router.post("/login", [
    body('email').isEmail().withMessage('Invalid email'),
    body('password').notEmpty().withMessage('Password is required'),
    // rateLimiter({ windowMs: 15 * 60 * 1000, max: 5 }) 
], login);

export default router;