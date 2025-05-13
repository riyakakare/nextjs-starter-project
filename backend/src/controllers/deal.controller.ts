import { Request, Response } from 'express';
import { prisma } from '../index';
import { AppError } from '../middleware/error.middleware';
import { z } from 'zod';
import { Decimal } from '@prisma/client/runtime/library';

const createDealSchema = z.object({
  toolId: z.string().uuid(),
  type: z.enum(['FREE', 'LIFETIME']),
  originalPrice: z.number().nonnegative(),
  dealPrice: z.number().nonnegative(),
  startDate: z.string().datetime(),
  endDate: z.string().datetime().optional(),
  features: z.array(z.string()),
  status: z.enum(['active', 'draft', 'expired']).default('active'),
});

export class DealController {
  async getAllDeals(req: Request, res: Response) {
    try {
      const deals = await prisma.deal.findMany({
        include: {
          tool: true,
        },
      });
      res.json(deals);
    } catch (error) {
      throw new AppError(500, 'Failed to fetch deals');
    }
  }

  async getDealById(req: Request, res: Response) {
    try {
      const { id } = req.params;
      const deal = await prisma.deal.findUnique({
        where: { id },
        include: {
          tool: true,
        },
      });

      if (!deal) {
        throw new AppError(404, 'Deal not found');
      }

      res.json(deal);
    } catch (error) {
      throw new AppError(500, 'Failed to fetch deal');
    }
  }

  async createDeal(req: Request, res: Response) {
    try {
      const data = createDealSchema.parse(req.body);

      // Verify tool ownership
      const tool = await prisma.tool.findUnique({
        where: { id: data.toolId },
      });

      if (!tool) {
        throw new AppError(404, 'Tool not found');
      }

      if (tool.vendorId !== req.user!.id) {
        throw new AppError(403, 'Not authorized to create deals for this tool');
      }

      // Check for existing active deals
      const existingDeal = await prisma.deal.findFirst({
        where: {
          toolId: data.toolId,
          status: 'active',
          endDate: {
            gt: new Date(),
          },
        },
      });

      if (existingDeal) {
        throw new AppError(400, 'An active deal already exists for this tool');
      }

      const deal = await prisma.deal.create({
        data: {
          ...data,
          originalPrice: new Decimal(data.originalPrice.toString()),
          dealPrice: new Decimal(data.dealPrice.toString()),
          startDate: new Date(data.startDate),
          endDate: data.endDate ? new Date(data.endDate) : null,
        },
        include: {
          tool: true,
        },
      });

      res.status(201).json(deal);
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new AppError(400, 'Invalid input', error.errors);
      }
      throw error;
    }
  }

  async updateDeal(req: Request, res: Response) {
    try {
      const { id } = req.params;
      const data = createDealSchema.partial().parse(req.body);

      const existingDeal = await prisma.deal.findUnique({
        where: { id },
        include: { tool: true },
      });

      if (!existingDeal) {
        throw new AppError(404, 'Deal not found');
      }

      if (existingDeal.tool.vendorId !== req.user!.id) {
        throw new AppError(403, 'Not authorized to update this deal');
      }

      const updatedDeal = await prisma.deal.update({
        where: { id },
        data: {
          ...data,
          originalPrice: data.originalPrice
            ? new Decimal(data.originalPrice.toString())
            : undefined,
          dealPrice: data.dealPrice
            ? new Decimal(data.dealPrice.toString())
            : undefined,
          startDate: data.startDate ? new Date(data.startDate) : undefined,
          endDate: data.endDate ? new Date(data.endDate) : undefined,
        },
        include: {
          tool: true,
        },
      });

      res.json(updatedDeal);
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new AppError(400, 'Invalid input', error.errors);
      }
      throw error;
    }
  }

  async deleteDeal(req: Request, res: Response) {
    try {
      const { id } = req.params;
      const existingDeal = await prisma.deal.findUnique({
        where: { id },
        include: { tool: true },
      });

      if (!existingDeal) {
        throw new AppError(404, 'Deal not found');
      }

      if (existingDeal.tool.vendorId !== req.user!.id) {
        throw new AppError(403, 'Not authorized to delete this deal');
      }

      await prisma.deal.delete({ where: { id } });
      res.status(204).send();
    } catch (error) {
      throw new AppError(500, 'Failed to delete deal');
    }
  }
}
