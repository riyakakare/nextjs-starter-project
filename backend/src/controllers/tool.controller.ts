import { Request, Response } from 'express';
import { prisma } from '../index';
import { AppError } from '../middleware/error.middleware';
import { z } from 'zod';
import { Decimal } from '@prisma/client/runtime/library';

const createToolSchema = z.object({
  name: z.string().min(3),
  description: z.string().min(10),
  price: z.number().nonnegative(),
  category: z.string().min(2),
  features: z.array(z.string()),
  tags: z.array(z.string()),
});

export class ToolController {
  async getAllTools(req: Request, res: Response) {
    try {
      const tools = await prisma.tool.findMany({
        include: {
          reviews: true,
          deals: true,
        },
      });
      res.json(tools);
    } catch (error) {
      throw new AppError(500, 'Failed to fetch tools');
    }
  }

  async getToolById(req: Request, res: Response) {
    try {
      const { id } = req.params;
      const tool = await prisma.tool.findUnique({
        where: { id },
        include: {
          reviews: true,
          deals: true,
        },
      });
      if (!tool) {
        throw new AppError(404, 'Tool not found');
      }
      res.json(tool);
    } catch (error) {
      throw new AppError(500, 'Failed to fetch tool');
    }
  }

  async createTool(req: Request, res: Response) {
    try {
      const data = createToolSchema.parse(req.body);
      const tool = await prisma.tool.create({
        data: {
          ...data,
          price: new Decimal(data.price.toString()),
          vendorId: req.user!.id,
        },
      });
      res.status(201).json(tool);
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new AppError(400, 'Invalid input', error.errors);
      }
      throw error;
    }
  }

  async updateTool(req: Request, res: Response) {
    try {
      const { id } = req.params;
      const data = createToolSchema.partial().parse(req.body);

      const existingTool = await prisma.tool.findUnique({ where: { id } });
      if (!existingTool) {
        throw new AppError(404, 'Tool not found');
      }
      if (existingTool.vendorId !== req.user!.id) {
        throw new AppError(403, 'Not authorized to update this tool');
      }

      const updatedTool = await prisma.tool.update({
        where: { id },
        data: {
          ...data,
          price: data.price ? new Decimal(data.price.toString()) : undefined,
        },
      });
      res.json(updatedTool);
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new AppError(400, 'Invalid input', error.errors);
      }
      throw error;
    }
  }

  async deleteTool(req: Request, res: Response) {
    try {
      const { id } = req.params;
      const existingTool = await prisma.tool.findUnique({ where: { id } });
      if (!existingTool) {
        throw new AppError(404, 'Tool not found');
      }
      if (existingTool.vendorId !== req.user!.id) {
        throw new AppError(403, 'Not authorized to delete this tool');
      }
      await prisma.tool.delete({ where: { id } });
      res.status(204).send();
    } catch (error) {
      throw new AppError(500, 'Failed to delete tool');
    }
  }
}
