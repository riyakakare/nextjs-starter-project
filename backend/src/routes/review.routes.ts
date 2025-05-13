import { Router } from 'express';
import { ReviewController } from '../controllers/review.controller';
import { authMiddleware } from '../middleware/auth.middleware';

const router = Router();
const reviewController = new ReviewController();

// Public routes
router.get('/', reviewController.getAllReviews);
router.get('/tool/:toolId', reviewController.getToolReviews);
router.get('/:id', reviewController.getReviewById);

// Protected routes
router.use(authMiddleware);
router.post('/', reviewController.createReview);
router.put('/:id', reviewController.updateReview);
router.delete('/:id', reviewController.deleteReview);

// Review voting
router.post('/:id/helpful', reviewController.markHelpful);
router.post('/:id/not-helpful', reviewController.markNotHelpful);

export default router;
