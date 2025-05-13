import { Router } from 'express';
import { AuthController } from '../controllers/auth.controller';
import { authMiddleware } from '../middleware/auth.middleware';
import { passwordValidationMiddleware } from '../middleware/password.middleware';
import { apiLimiter, authLimiter } from '../middleware/security.middleware';

const router = Router();
const authController = new AuthController();

// Public routes with rate limiting
router.post('/register', authLimiter, passwordValidationMiddleware, authController.register);
router.post('/login', authLimiter, authController.login);

// Protected routes
router.use(authMiddleware);
router.use(apiLimiter);

// Password management
router.post(
  '/change-password',
  passwordValidationMiddleware,
  authController.changePassword
);

export default router;
