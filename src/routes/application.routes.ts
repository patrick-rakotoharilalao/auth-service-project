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

/**
 * @swagger
 * /api/applications:
 *   get:
 *     summary: List all applications (Admin only)
 *     description: Retrieves all applications with optional filtering by active status. API keys are masked for security.
 *     tags: [Applications]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: query
 *         name: isActive
 *         schema:
 *           type: string
 *           enum: [true, false]
 *         description: Filter by active status
 *         example: true
 *     responses:
 *       200:
 *         description: Applications retrieved successfully
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
 *                   example: Applications retrieved successfully
 *                 data:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: string
 *                       name:
 *                         type: string
 *                       description:
 *                         type: string
 *                       apiKey:
 *                         type: string
 *                         description: Masked API key (e.g., app_1234***xyz9)
 *                       allowedOrigins:
 *                         type: array
 *                         items:
 *                           type: string
 *                       webhookUrl:
 *                         type: string
 *                       isActive:
 *                         type: boolean
 *                       createdAt:
 *                         type: string
 *                         format: date-time
 *                       updatedAt:
 *                         type: string
 *                         format: date-time
 *       401:
 *         description: Unauthorized - Invalid or missing token
 *       403:
 *         description: Forbidden - Admin access required
 */
router.get('/', authenticate, requireAdmin, getAllApplications);

/**
 * @swagger
 * /api/applications/{id}:
 *   get:
 *     summary: Get application by ID (Admin only)
 *     description: Retrieves detailed information about a specific application. API key is masked for security.
 *     tags: [Applications]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Application ID
 *         example: 550e8400-e29b-41d4-a716-446655440000
 *     responses:
 *       200:
 *         description: Application retrieved successfully
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
 *                   example: Application retrieved successfully
 *                 data:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                     name:
 *                       type: string
 *                     description:
 *                       type: string
 *                     apiKey:
 *                       type: string
 *                       description: Masked API key
 *                     allowedOrigins:
 *                       type: array
 *                       items:
 *                         type: string
 *                     webhookUrl:
 *                       type: string
 *                     isActive:
 *                       type: boolean
 *                     createdAt:
 *                       type: string
 *                       format: date-time
 *                     updatedAt:
 *                       type: string
 *                       format: date-time
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden - Admin access required
 *       404:
 *         description: Application not found
 */
router.get('/:id', authenticate, requireAdmin, getApplicationById);

/**
 * @swagger
 * /api/applications/{id}:
 *   patch:
 *     summary: Update application (Admin only)
 *     description: Updates application details. API key cannot be modified through this endpoint.
 *     tags: [Applications]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Application ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *                 minLength: 3
 *                 maxLength: 100
 *                 example: Updated App Name
 *               description:
 *                 type: string
 *                 maxLength: 500
 *                 example: Updated description
 *               allowedOrigins:
 *                 type: array
 *                 minItems: 1
 *                 items:
 *                   type: string
 *                   format: uri
 *                 example: ["https://newdomain.com"]
 *               webhookUrl:
 *                 type: string
 *                 format: uri
 *                 example: https://newdomain.com/webhooks
 *     responses:
 *       200:
 *         description: Application updated successfully
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
 *                   example: Application updated successfully
 *                 data:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                     name:
 *                       type: string
 *                     description:
 *                       type: string
 *                     apiKey:
 *                       type: string
 *                       description: Masked API key
 *                     allowedOrigins:
 *                       type: array
 *                       items:
 *                         type: string
 *                     webhookUrl:
 *                       type: string
 *                     isActive:
 *                       type: boolean
 *                     updatedAt:
 *                       type: string
 *                       format: date-time
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden - Admin access required
 *       404:
 *         description: Application not found
 *       422:
 *         description: Validation error
 */
router.patch('/:id', [
    authenticate,
    requireAdmin,
    body('name').optional().isLength({ min: 3, max: 100 }),
    body('description').optional().isLength({ max: 500 }),
    body('allowedOrigins').optional().isArray({ min: 1 }),
    body('webhookUrl').optional().isURL()
], updateApplication);

/**
 * @swagger
 * /api/applications/{id}/regenerate-key:
 *   post:
 *     summary: Regenerate API key (Admin only)
 *     description: Generates a new API key and invalidates the old one. The new key is shown only once - save it securely.
 *     tags: [Applications]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Application ID
 *     responses:
 *       200:
 *         description: API Key regenerated successfully
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
 *                   example: API Key regenerated successfully. Save it now, it will not be shown again.
 *                 data:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                     name:
 *                       type: string
 *                     apiKey:
 *                       type: string
 *                       description: New API key (shown only once)
 *                       example: app_abc123def456...
 *                     updatedAt:
 *                       type: string
 *                       format: date-time
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden - Admin access required
 *       404:
 *         description: Application not found
 */
router.post('/:id/regenerate-key', authenticate, requireAdmin, regenerateApiKey);

/**
 * @swagger
 * /api/applications/{id}/toggle:
 *   patch:
 *     summary: Toggle application active status (Admin only)
 *     description: Activates or deactivates an application. Deactivated applications cannot be used for authentication.
 *     tags: [Applications]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Application ID
 *     responses:
 *       200:
 *         description: Application status toggled successfully
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
 *                   example: Application activated successfully
 *                 data:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                     name:
 *                       type: string
 *                     isActive:
 *                       type: boolean
 *                       description: Current active status
 *                     updatedAt:
 *                       type: string
 *                       format: date-time
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden - Admin access required
 *       404:
 *         description: Application not found
 */
router.patch('/:id/toggle', authenticate, requireAdmin, toggleActive);

/**
 * @swagger
 * /api/applications/{id}:
 *   delete:
 *     summary: Delete application (Admin only)
 *     description: Deletes an application. Fails if users have access unless force=true is used.
 *     tags: [Applications]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Application ID
 *       - in: query
 *         name: force
 *         schema:
 *           type: string
 *           enum: [true, false]
 *         description: Force deletion even if users have access
 *         example: false
 *     responses:
 *       200:
 *         description: Application deleted successfully
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
 *                   example: Application deleted successfully
 *                 data:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                     name:
 *                       type: string
 *       400:
 *         description: Cannot delete - users have access (use force=true to override)
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden - Admin access required
 *       404:
 *         description: Application not found
 */
router.delete('/:id', authenticate, requireAdmin, deleteApplication);

/**
 * @swagger
 * /api/applications/{id}/users:
 *   get:
 *     summary: List users of an application (Admin only)
 *     description: Retrieves all users who have access to a specific application with their roles.
 *     tags: [Applications]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Application ID
 *     responses:
 *       200:
 *         description: Application users retrieved successfully
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
 *                   example: Application users retrieved successfully
 *                 data:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       userId:
 *                         type: string
 *                       email:
 *                         type: string
 *                       role:
 *                         type: string
 *                         enum: [owner, admin, user, viewer]
 *                         description: User's role in this application
 *                       emailVerified:
 *                         type: boolean
 *                       userCreatedAt:
 *                         type: string
 *                         format: date-time
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden - Admin access required
 *       404:
 *         description: Application not found
 */
router.get('/:id/users', authenticate, requireAdmin, getUsersByApp);

/**
 * @swagger
 * /api/applications/{id}/users:
 *   post:
 *     summary: Add user to application (Admin only)
 *     description: Grants a user access to an application with a specific role.
 *     tags: [Applications]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Application ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - userId
 *             properties:
 *               userId:
 *                 type: string
 *                 description: ID of the user to add
 *                 example: 550e8400-e29b-41d4-a716-446655440000
 *               role:
 *                 type: string
 *                 enum: [admin, user, viewer]
 *                 default: user
 *                 description: Role to assign to the user
 *                 example: user
 *     responses:
 *       201:
 *         description: User added to application successfully
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
 *                   example: User added to application successfully
 *                 data:
 *                   type: object
 *                   properties:
 *                     userId:
 *                       type: string
 *                     userEmail:
 *                       type: string
 *                     applicationId:
 *                       type: string
 *                     role:
 *                       type: string
 *                     createdAt:
 *                       type: string
 *                       format: date-time
 *       400:
 *         description: User already has access to this application
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden - Admin access required
 *       404:
 *         description: Application or user not found
 *       422:
 *         description: Validation error
 */
router.post('/:id/users', [
    authenticate,
    requireAdmin,
    body('userId').notEmpty().withMessage('User ID is required'),
    body('role').optional().isIn(['admin', 'user', 'viewer']).withMessage('Invalid role')
], addUserToApp);


/**
 * @swagger
 * /api/applications/{id}/users/{userId}:
 *   delete:
 *     summary: Remove user from application (Admin only)
 *     description: Revokes a user's access to an application.
 *     tags: [Applications]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Application ID
 *       - in: path
 *         name: userId
 *         required: true
 *         schema:
 *           type: string
 *         description: User ID to remove
 *     responses:
 *       200:
 *         description: User removed from application successfully
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
 *                   example: User removed from application successfully
 *                 data:
 *                   type: object
 *                   properties:
 *                     userId:
 *                       type: string
 *                     userEmail:
 *                       type: string
 *                     applicationId:
 *                       type: string
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden - Admin access required
 *       404:
 *         description: Application, user, or user access not found
 */
router.delete('/:id/users/:userId', authenticate, requireAdmin, removeUserFromApp);

export default router;