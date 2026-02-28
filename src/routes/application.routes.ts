import { addUserToApp, createApplication, deleteApplication, getAllApplications, getApplicationById, getUsersByApp, regenerateApiKey, removeUserFromApp, toggleActive, updateApplication } from "@/controllers/application.controller";
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

router.get('/', authenticate, requireAdmin, getAllApplications);
router.get('/:id', authenticate, requireAdmin, getApplicationById);
router.patch('/:id', [
    authenticate,
    requireAdmin,
    body('name').optional().isLength({ min: 3, max: 100 }),
    body('description').optional().isLength({ max: 500 }),
    body('allowedOrigins').optional().isArray({ min: 1 }),
    body('webhookUrl').optional().isURL()
], updateApplication);
router.post('/:id/regenerate-key', authenticate, requireAdmin, regenerateApiKey);
router.patch('/:id/toggle', authenticate, requireAdmin, toggleActive);
router.delete('/:id', authenticate, requireAdmin, deleteApplication);
router.get('/:id/users', authenticate, requireAdmin, getUsersByApp);
router.post('/:id/users', [
    authenticate,
    requireAdmin,
    body('userId').notEmpty().withMessage('User ID is required'),
    body('role').optional().isIn(['admin', 'user', 'viewer']).withMessage('Invalid role')
], addUserToApp);
router.delete('/:id/users/:userId', authenticate, requireAdmin, removeUserFromApp);

export default router;