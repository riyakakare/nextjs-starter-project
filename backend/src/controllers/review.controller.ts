import { Request, Response } from 'express';
import { prisma } from '../index';
import { AppError } from '../middleware/error.middleware';
import { z } from 'zod';

const createReviewSchema = z.object({
  toolId: z.string().uuid(),
  rating: z.number().min(1).max(5),
  content: z.string().min(10),
});

export class ReviewController {
  async getAllReviews(req: Request, res: Response) {
    try {
      const reviews = await prisma.review.findMany({
        include: {
          user: {
            select: {
              id: true,
              name: true,
            },
          },
          tool: true,
        },
      });
      res.json(reviews);
    } catch (error) {
      throw new AppError(500, 'Failed to fetch reviews');
    }
  }

  async getToolReviews(req: Request, res: Response) {
    try {
      const { toolId } = req.params;
      const reviews = await prisma.review.findMany({
        where: { toolId },
        include: {
          user: {
            select: {
              id: true,
              name: true,
            },
          },
        },
        orderBy: {
          createdAt: 'desc',
        },
      });
      res.json(reviews);
    } catch (error) {
      throw new AppError(500, 'Failed to fetch tool reviews');
    }
  }

  async getReviewById(req: Request, res: Response) {
    try {
      const { id } = req.params;
      const review = await prisma.review.findUnique({
        where: { id },
        include: {
          user: {
            select: {
              id: true,
              name: true,
            },
          },
          tool: true,
        },
      });

      if (!review) {
        throw new AppError(404, 'Review not found');
      }

      res.json(review);
    } catch (error) {
      throw new AppError(500, 'Failed to fetch review');
    }
  }

  async createReview(req: Request, res: Response) {
    try {
      const data = createReviewSchema.parse(req.body);

      // Check if tool exists
      const tool = await prisma.tool.findUnique({
        where: { id: data.toolId },
      });

      if (!tool) {
        throw new AppError(404, 'Tool not found');
      }

      // Check if user has already reviewed this tool
      const existingReview = await prisma.review.findFirst({
        where: {
          toolId: data.toolId,
          userId: req.user!.id,
        },
      });

      if (existingReview) {
        throw new AppError(400, 'You have already reviewed this tool');
      }

      // Create review
      const review = await prisma.review.create({
        data: {
          ...data,
          userId: req.user!.id,
        },
        include: {
          user: {
            select: {
              id: true,
              name: true,
            },
          },
        },
      });

      res.status(201).json(review);
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new AppError(400, 'Invalid input', error.errors);
      }
      throw error;
    }
  }

  async updateReview(req: Request, res: Response) {
    try {
      const { id } = req.params;
      const data = createReviewSchema.partial().parse(req.body);

      const existingReview = await prisma.review.findUnique({
        where: { id },
      });

      if (!existingReview) {
        throw new AppError(404, 'Review not found');
      }

      if (existingReview.userId !== req.user!.id) {
        throw new AppError(403, 'Not authorized to update this review');
      }

      const updatedReview = await prisma.review.update({
        where: { id },
        data,
        include: {
          user: {
            select: {
              id: true,
              name: true,
            },
          },
        },
      });

      res.json(updatedReview);
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new AppError(400, 'Invalid input', error.errors);
      }
      throw error;
    }
  }

  async deleteReview(req: Request, res: Response) {
    try {
      const { id } = req.params;
      const existingReview = await prisma.review.findUnique({
        where: { id },
      });

      if (!existingReview) {
        throw new AppError(404, 'Review not found');
      }

      if (existingReview.userId !== req.user!.id) {
        throw new AppError(403, 'Not authorized to delete this review');
      }

      await prisma.review.delete({ where: { id } });
      res.status(204).send();
    } catch (error) {
      throw new AppError(500, 'Failed to delete review');
    }
  }

  async markHelpful(req: Request, res: Response) {
    try {
      const { id } = req.params;
      const review = await prisma.review.update({
        where: { id },
        data: {
          helpful: {
            increment: 1,
          },
        },
      });
      res.json(review);
    } catch (error) {
      throw new AppError(500, 'Failed to mark review as helpful');
    }
  }

  async markNotHelpful(req: Request, res: Response) {
    try {
      const { id } = req.params;
      const review = await prisma.review.update({
        where: { id },
        data: {
          notHelpful: {
            increment: 1,
          },
        },
      });
      res.json(review);
    } catch (error) {
      throw new AppError(500, 'Failed to mark review as not helpful');
    }
  }
}
