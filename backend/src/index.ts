import express from 'express';
import { PrismaClient } from '@prisma/client';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { 
  securityHeaders, 
  sessionMiddleware, 
  sanitizeRequest, 
  ipBlockingMiddleware,
  requestSizeLimiter,
  sqlInjectionPrevention,
  csrfProtection
} from './middleware/security.middleware';
import { errorHandler } from './middleware/error.middleware';
import authRoutes from './routes/auth.routes';
import toolRoutes from './routes/tool.routes';
import dealRoutes from './routes/deal.routes';
import reviewRoutes from './routes/review.routes';

// Create Express app
const app = express();

// Initialize Prisma client
export const prisma = new PrismaClient();

// Basic middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Security middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
}));
app.use(securityHeaders);
app.use(sessionMiddleware);
app.use(sanitizeRequest);
app.use(ipBlockingMiddleware);
app.use(requestSizeLimiter);
app.use(sqlInjectionPrevention);
app.use(csrfProtection);

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/tools', toolRoutes);
app.use('/api/deals', dealRoutes);
app.use('/api/reviews', reviewRoutes);

// Error handling
app.use(errorHandler);

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

// Handle shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received. Closing HTTP server and Prisma client...');
  await prisma.$disconnect();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('SIGINT received. Closing HTTP server and Prisma client...');
  await prisma.$disconnect();
  process.exit(0);
});

export default app;
