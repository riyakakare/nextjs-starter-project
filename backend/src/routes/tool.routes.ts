import { Router } from 'express';
import { ToolController } from '../controllers/tool.controller';
import { authMiddleware } from '../middleware/auth.middleware';
import { vendorMiddleware } from '../middleware/vendor.middleware';

const router = Router();
const toolController = new ToolController();

// Public routes
router.get('/', toolController.getAllTools);
router.get('/:id', toolController.getToolById);

// Protected routes (requires authentication)
router.use(authMiddleware);

// Vendor-only routes
router.post('/', vendorMiddleware, toolController.createTool);
router.put('/:id', vendorMiddleware, toolController.updateTool);
router.delete('/:id', vendorMiddleware, toolController.deleteTool);

export default router;
