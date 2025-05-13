import { Router } from 'express';
import { DealController } from '../controllers/deal.controller';
import { authMiddleware } from '../middleware/auth.middleware';
import { vendorMiddleware } from '../middleware/vendor.middleware';

const router = Router();
const dealController = new DealController();

// Public routes
router.get('/', dealController.getAllDeals);
router.get('/:id', dealController.getDealById);

// Protected routes
router.use(authMiddleware);

// Vendor-only routes
router.post('/', vendorMiddleware, dealController.createDeal);
router.put('/:id', vendorMiddleware, dealController.updateDeal);
router.delete('/:id', vendorMiddleware, dealController.deleteDeal);

export default router;
