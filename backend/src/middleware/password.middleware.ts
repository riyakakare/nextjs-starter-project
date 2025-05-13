import { Request, Response, NextFunction } from 'express';
import { AppError } from './error.middleware';
import zxcvbn from 'zxcvbn';
import bcrypt from 'bcryptjs';
import { prisma } from '../index';

interface PasswordRequirements {
  minLength: number;
  minScore: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireNumbers: boolean;
  requireSpecialChars: boolean;
}

const DEFAULT_PASSWORD_REQUIREMENTS: PasswordRequirements = {
  minLength: 8,
  minScore: 3, // zxcvbn score (0-4)
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecialChars: true,
};

export const validatePassword = (
  password: string,
  requirements: PasswordRequirements = DEFAULT_PASSWORD_REQUIREMENTS
): { isValid: boolean; errors: string[] } => {
  const errors: string[] = [];

  // Check minimum length
  if (password.length < requirements.minLength) {
    errors.push(`Password must be at least ${requirements.minLength} characters long`);
  }

  // Check character requirements
  if (requirements.requireUppercase && !/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }
  if (requirements.requireLowercase && !/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }
  if (requirements.requireNumbers && !/\d/.test(password)) {
    errors.push('Password must contain at least one number');
  }
  if (requirements.requireSpecialChars && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    errors.push('Password must contain at least one special character');
  }

  // Check password strength using zxcvbn
  const strengthResult = zxcvbn(password);
  if (strengthResult.score < requirements.minScore) {
    errors.push('Password is too weak. Please choose a stronger password');
    
    // Add specific feedback from zxcvbn if available
    if (strengthResult.feedback.suggestions.length > 0) {
      errors.push(...strengthResult.feedback.suggestions);
    }
  }

  return {
    isValid: errors.length === 0,
    errors,
  };
};

export const passwordValidationMiddleware = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const password = req.body.password;

  if (!password) {
    next();
    return;
  }

  const validation = validatePassword(password);

  if (!validation.isValid) {
    throw new AppError(400, 'Password validation failed', validation.errors);
  }

  next();
};

export const preventPasswordReuse = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const { userId, password } = req.body;

  if (!userId || !password) {
    next();
    return;
  }

  // Get user's password history from database
  const passwordHistory = await prisma.user.findUnique({
    where: { id: userId },
    select: {
      passwordHistory: true,
    },
  });

  if (!passwordHistory) {
    next();
    return;
  }

  // Check if the new password matches any of the previous passwords
  const isPasswordReused = await Promise.all(
    passwordHistory.passwordHistory.map((oldPassword: string) => 
      bcrypt.compare(password, oldPassword)
    )
  ).then(results => results.some(result => result));

  if (isPasswordReused) {
    throw new AppError(400, 'Password has been used before. Please choose a different password');
  }

  next();
};

// Password expiration check middleware
export const checkPasswordExpiration = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const userId = req.user?.id;

  if (!userId) {
    next();
    return;
  }

  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: {
      passwordUpdatedAt: true,
    },
  });

  if (!user) {
    next();
    return;
  }

  const PASSWORD_EXPIRATION_DAYS = 90; // Password expires after 90 days
  const passwordAge = Math.floor(
    (Date.now() - user.passwordUpdatedAt.getTime()) / (1000 * 60 * 60 * 24)
  );

  if (passwordAge >= PASSWORD_EXPIRATION_DAYS) {
    throw new AppError(401, 'Password has expired. Please reset your password');
  }

  next();
};
