import { Request, Response, NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import session from 'express-session';
import { prisma } from '../index';
import { AppError } from './error.middleware';

declare module 'express-session' {
  interface SessionData {
    csrfToken: string;
    userId: string;
  }
}

// IP Blocking
const blockedIPs = new Set<string>();

// Rate limiting configuration
export const createRateLimiter = (options: {
  windowMs: number;
  max: number;
  message: string;
}) => {
  return rateLimit({
    windowMs: options.windowMs,
    max: options.max,
    message: { error: options.message },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.ip || 'unknown',
    handler: (req, res) => {
      throw new AppError(429, options.message);
    },
  });
};

// Different rate limiters for different routes
export const authLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts
  message: 'Too many login attempts, please try again later',
});

export const apiLimiter = createRateLimiter({
  windowMs: 60 * 1000, // 1 minute
  max: 100, // 100 requests per minute
  message: 'Too many requests, please try again later',
});

// Security headers middleware using helmet
export const securityHeaders = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy: true,
  crossOriginResourcePolicy: { policy: "same-site" },
  dnsPrefetchControl: true,
  frameguard: { action: "deny" },
  hidePoweredBy: true,
  hsts: true,
  ieNoOpen: true,
  noSniff: true,
  referrerPolicy: { policy: "same-origin" },
  xssFilter: true,
});

// Session configuration
export const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'strict',
  },
});

// IP Blocking middleware
export const ipBlockingMiddleware = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const clientIP = req.ip || 'unknown';

  if (blockedIPs.has(clientIP)) {
    throw new AppError(403, 'Your IP has been blocked');
  }

  // Check for suspicious activity
  const recentRequests = await prisma.auditLog.count({
    where: {
      ip: clientIP,
      createdAt: {
        gte: new Date(Date.now() - 5 * 60 * 1000), // Last 5 minutes
      },
      action: 'FAILED_LOGIN',
    },
  });

  if (recentRequests > 10) {
    blockedIPs.add(clientIP);
    throw new AppError(403, 'Your IP has been blocked due to suspicious activity');
  }

  next();
};

// Request sanitization middleware
export const sanitizeRequest = (req: Request, res: Response, next: NextFunction) => {
  const sanitizeValue = (value: any): any => {
    if (typeof value === 'string') {
      // Remove potential XSS content
      return value
        .replace(/[<>]/g, '')
        .replace(/javascript:/gi, '')
        .replace(/on\w+=/gi, '')
        .trim();
    }
    if (typeof value === 'object' && value !== null) {
      return Object.keys(value).reduce((acc: any, key) => {
        acc[key] = sanitizeValue(value[key]);
        return acc;
      }, Array.isArray(value) ? [] : {});
    }
    return value;
  };

  req.body = sanitizeValue(req.body);
  req.query = sanitizeValue(req.query);
  req.params = sanitizeValue(req.params);

  next();
};

// CSRF Protection
export const csrfProtection = (req: Request, res: Response, next: NextFunction) => {
  if (req.method === 'GET') {
    // Generate new CSRF token for GET requests
    const token = Math.random().toString(36).substring(2);
    req.session.csrfToken = token;
    res.setHeader('X-CSRF-Token', token);
    next();
    return;
  }

  const token = req.headers['x-csrf-token'];
  const expectedToken = req.session?.csrfToken;

  if (!token || !expectedToken || token !== expectedToken) {
    throw new AppError(403, 'Invalid CSRF token');
  }

  next();
};

// Request size limiting middleware
export const requestSizeLimiter = (req: Request, res: Response, next: NextFunction) => {
  const contentLength = parseInt(req.headers['content-length'] || '0');
  const MAX_SIZE = 10 * 1024 * 1024; // 10MB

  if (contentLength > MAX_SIZE) {
    throw new AppError(413, 'Request entity too large');
  }

  next();
};

// SQL Injection prevention middleware
export const sqlInjectionPrevention = (req: Request, res: Response, next: NextFunction) => {
  const sqlInjectionPattern = /(\b(select|insert|update|delete|drop|union|exec|declare)\b)|(['"])/gi;
  
  const checkValue = (value: any): boolean => {
    if (typeof value === 'string' && sqlInjectionPattern.test(value)) {
      return true;
    }
    if (typeof value === 'object' && value !== null) {
      return Object.values(value).some(v => checkValue(v));
    }
    return false;
  };

  if (
    checkValue(req.body) ||
    checkValue(req.query) ||
    checkValue(req.params)
  ) {
    throw new AppError(403, 'Potential SQL injection detected');
  }

  next();
};
