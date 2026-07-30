import dotenv from 'dotenv';
dotenv.config();

const requiredEnv = ['POSTGRES_USER', 'POSTGRES_PASSWORD', 'POSTGRES_HOST', 'POSTGRES_PORT', 'POSTGRES_DB'];
for (const envVar of requiredEnv) {
  if (!process.env[envVar]) {
    throw new Error(`Missing required database environment variable: ${envVar}`);
  }
}

const dbUser = encodeURIComponent(process.env.POSTGRES_USER);
const dbPassword = encodeURIComponent(process.env.POSTGRES_PASSWORD);
const dbHost = process.env.POSTGRES_HOST;
const dbPort = process.env.POSTGRES_PORT;
const dbName = process.env.POSTGRES_DB;

export const config = {
  port: process.env.PORT || 3000,
  databaseUrl: `postgresql://${dbUser}:${dbPassword}@${dbHost}:${dbPort}/${dbName}?schema=public`,
  jwtSecret: process.env.JWT_SECRET,
};
