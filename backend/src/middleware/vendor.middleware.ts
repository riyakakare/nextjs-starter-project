import { Request, Response, NextFunction } from 'express';
import { AppError } from './error.middleware';

export const vendorMiddleware = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    if (!req.user) {
      throw new AppError(401, 'Authentication required');
    }

    if (req.user.role !== 'VENDOR') {
      throw new AppError(403, 'Vendor access required');
    }

    next();
  } catch (error) {
    next(error);
  }
};
