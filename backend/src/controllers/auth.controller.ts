import { Request, Response } from 'express';
import { prisma } from '../index';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { AppError } from '../middleware/error.middleware';
import { validatePassword } from '../middleware/password.middleware';
import { Prisma } from '@prisma/client';

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  name: z.string().min(2),
  role: z.enum(['USER', 'VENDOR']).default('USER'),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string(),
});

export class AuthController {
  async register(req: Request, res: Response) {
    try {
      const { email, password, name, role } = registerSchema.parse(req.body);

      // Validate password strength
      const passwordValidation = validatePassword(password);
      if (!passwordValidation.isValid) {
        throw new AppError(400, 'Password validation failed', passwordValidation.errors);
      }

      // Check if user already exists
      const existingUser = await prisma.user.findUnique({
        where: { email },
        select: {
          id: true,
        },
      });

      if (existingUser) {
        throw new AppError(400, 'User already exists');
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 12);

      // Create user with password history
      const user = await prisma.user.create({
        data: {
          email,
          password: hashedPassword,
          name,
          role,
          passwordHistory: [hashedPassword],
          passwordUpdatedAt: new Date(),
        },
        select: {
          id: true,
          email: true,
          name: true,
          role: true,
        },
      });

      // Log the registration
      const metadata: Prisma.JsonObject = {
        email: user.email,
        role: user.role,
      };

      await prisma.auditLog.create({
        data: {
          action: 'REGISTER',
          resource: 'auth',
          details: `User registration: ${email}`,
          userId: user.id,
          ip: req.ip || 'unknown',
          userAgent: req.headers['user-agent'],
          metadata,
        },
      });

      // Generate JWT
      const token = jwt.sign(
        { userId: user.id },
        process.env.JWT_SECRET || 'your-secret-key',
        { expiresIn: '1d' }
      );

      return res.status(201).json({
        message: 'User registered successfully',
        user,
        token,
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new AppError(400, 'Invalid input', error.errors);
      }
      throw error;
    }
  }

  async login(req: Request, res: Response) {
    try {
      const { email, password } = loginSchema.parse(req.body);

      // Find user
      const user = await prisma.user.findUnique({
        where: { email },
        select: {
          id: true,
          email: true,
          password: true,
          name: true,
          role: true,
          passwordUpdatedAt: true,
        },
      });

      if (!user) {
        const metadata: Prisma.JsonObject = {
          email,
          reason: 'User not found',
        };

        await prisma.auditLog.create({
          data: {
            action: 'FAILED_LOGIN',
            resource: 'auth',
            details: `Failed login attempt for email: ${email}`,
            ip: req.ip || 'unknown',
            userAgent: req.headers['user-agent'],
            metadata,
          },
        });
        throw new AppError(401, 'Invalid credentials');
      }

      // Verify password
      const isValidPassword = await bcrypt.compare(password, user.password);

      if (!isValidPassword) {
        const metadata: Prisma.JsonObject = {
          email,
          reason: 'Invalid password',
        };

        await prisma.auditLog.create({
          data: {
            action: 'FAILED_LOGIN',
            resource: 'auth',
            details: `Failed login attempt for user: ${user.id}`,
            userId: user.id,
            ip: req.ip || 'unknown',
            userAgent: req.headers['user-agent'],
            metadata,
          },
        });
        throw new AppError(401, 'Invalid credentials');
      }

      // Check if password has expired
      const PASSWORD_EXPIRATION_DAYS = 90;
      const passwordAge = Math.floor(
        (Date.now() - user.passwordUpdatedAt.getTime()) / (1000 * 60 * 60 * 24)
      );

      if (passwordAge >= PASSWORD_EXPIRATION_DAYS) {
        throw new AppError(401, 'Password has expired. Please reset your password');
      }

      // Log successful login
      const metadata: Prisma.JsonObject = {
        email: user.email,
      };

      await prisma.auditLog.create({
        data: {
          action: 'LOGIN',
          resource: 'auth',
          details: `Successful login for user: ${user.id}`,
          userId: user.id,
          ip: req.ip || 'unknown',
          userAgent: req.headers['user-agent'],
          metadata,
        },
      });

      // Generate JWT
      const token = jwt.sign(
        { userId: user.id },
        process.env.JWT_SECRET || 'your-secret-key',
        { expiresIn: '1d' }
      );

      return res.json({
        message: 'Logged in successfully',
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
        },
        token,
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new AppError(400, 'Invalid input', error.errors);
      }
      throw error;
    }
  }

  async changePassword(req: Request, res: Response) {
    try {
      const { currentPassword, newPassword } = req.body;
      const userId = req.user!.id;

      // Validate new password strength
      const passwordValidation = validatePassword(newPassword);
      if (!passwordValidation.isValid) {
        throw new AppError(400, 'Password validation failed', passwordValidation.errors);
      }

      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: {
          id: true,
          password: true,
          passwordHistory: true,
        },
      });

      if (!user) {
        throw new AppError(404, 'User not found');
      }

      // Verify current password
      const isValidPassword = await bcrypt.compare(currentPassword, user.password);
      if (!isValidPassword) {
        throw new AppError(401, 'Current password is incorrect');
      }

      // Check if new password matches any previous passwords
      const isPasswordReused = await Promise.all(
        user.passwordHistory.map((oldPassword: string) => 
          bcrypt.compare(newPassword, oldPassword)
        )
      ).then((results: boolean[]) => results.some(result => result));

      if (isPasswordReused) {
        throw new AppError(400, 'Password has been used before. Please choose a different password');
      }

      // Hash new password
      const hashedPassword = await bcrypt.hash(newPassword, 12);

      // Update user with new password and add to history
      const MAX_PASSWORD_HISTORY = 5;
      await prisma.user.update({
        where: { id: userId },
        data: {
          password: hashedPassword,
          passwordHistory: [...user.passwordHistory, hashedPassword].slice(-MAX_PASSWORD_HISTORY),
          passwordUpdatedAt: new Date(),
        },
      });

      // Log password change
      const metadata: Prisma.JsonObject = {
        userId: user.id,
      };

      await prisma.auditLog.create({
        data: {
          action: 'PASSWORD_CHANGE',
          resource: 'auth',
          details: `Password changed for user: ${userId}`,
          userId: user.id,
          ip: req.ip || 'unknown',
          userAgent: req.headers['user-agent'],
          metadata,
        },
      });

      return res.json({
        message: 'Password changed successfully',
      });
    } catch (error) {
      throw error;
    }
  }
}
