import express from 'express';
import cors from 'cors';
import pg from 'pg';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '@prisma/client';
import connectionRoutes from './routes/connection.routes.js';
import { config } from './config.js';

const app = express();

const pool = new pg.Pool({
  connectionString: config.databaseUrl
});

const adapter = new PrismaPg(pool);

const prisma = new PrismaClient({
  adapter
});

// Test connection on startup and log result
prisma.$connect()
  .then(() => {
    console.log('Database connected successfully via Prisma');
  })
  .catch((err) => {
    console.error('Failed to connect to the database on startup:', err.message);
  });

app.use(cors());
app.use(express.json());

app.get('/health', async (req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;

    res.json({
      status: 'ok',
      service: 'express-api',
      database: 'healthy'
    });
  } catch (error) {
    res.status(500).json({
      status: 'error',
      database: 'unhealthy',
      error: error.message
    });
  }
});

app.use('/connections', connectionRoutes);

// Global JSON error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal Server Error' });
});

app.listen(config.port, () => {
  console.log(`Express API running on port ${config.port}`);
});