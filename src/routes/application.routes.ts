import { createApplication } from "@/controllers/application.controller";
import { authenticate } from "@/middlewares/auth.middleware";
import { requireAdmin } from "@/middlewares/requireAdmin.middleware";
import { Router } from "express";
import { body } from "express-validator";

const router = Router();

router.post('/', [
    authenticate,
    requireAdmin,
    body('name').notEmpty().withMessage('Name is required'),
    body('allowedOrigins')
        .notEmpty().withMessage('Must have at least one allowed origin')
        .isArray({ min: 1 }).withMessage('Must be an array with at least one origin')
        .custom((origins: string[]) => {
            return origins.every(origin => /^https?:\/\/.+/.test(origin));
        }).withMessage('Each origin must be a valid URL')
        .custom((origins: string[]) => {
            return new Set(origins).size === origins.length;
        }).withMessage('Duplicate origins not allowed'),
    body('webhookUrl')
        .notEmpty().withMessage('webhookUrl is required')
        .isURL().withMessage('Must be a valid URL')
        .isLength({ max: 500 }).withMessage('URL too long')

], createApplication);

export default router;