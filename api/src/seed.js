import pg from 'pg';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '@prisma/client';
import { config } from './config.js';

const pool = new pg.Pool({
  connectionString: config.databaseUrl
});

const adapter = new PrismaPg(pool);
const prisma = new PrismaClient({ adapter });

async function seed() {
  console.log('--- Starting Database Seed ---');

  // 1. Ensure user exists
  const email = 'testuser@example.com';
  const password = 'Password123';

  let user = await prisma.users.findFirst({
    where: { email }
  });

  const GOTRUE_URL = process.env.EXPRESS_GOTRUE_URL;
  if (!GOTRUE_URL) {
    throw new Error("EXPRESS_GOTRUE_URL is not set. Cannot seed database.");
  }

  if (!user) {
    console.log(`Test user (${email}) not found. Creating via GoTrue...`);
    try {
      const authUrl = GOTRUE_URL;
      const response = await fetch(`${authUrl}/signup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });

      if (!response.ok) {
        const errText = await response.text();
        throw new Error(`Failed to create user: ${errText}`);
      }

      console.log('Test user created successfully via GoTrue!');

      // Give DB a moment to sync
      await new Promise(r => setTimeout(r, 1000));
      user = await prisma.users.findFirst({ where: { email } });

    } catch (err) {
      throw new Error(`Error connecting to GoTrue API: ${err.message}`);
    }
  }

  if (!user) {
    throw new Error('Failed to create user');
  }

  const userId = user.id;
  console.log(`Using Test User ID: ${userId}`);

  // 2. We don't seed rules here because they are seeded in db/02_seed.sql
  // We will just seed Connections, Scans, etc. if they don't exist for this user.

  const existingConnection = await prisma.connections.findFirst({
    where: { user_id: userId, name: 'Production AWS Account' }
  });

  if (!existingConnection) {
    console.log('Seeding dummy connection and scan data...');
    const connection = await prisma.connections.create({
      data: {
        user_id: userId,
        name: 'Production AWS Account',
        provider: 'aws',
        credentials: { "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE", "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "region": "us-east-1" }
      }
    });

    const scanJob = await prisma.scan_jobs.create({
      data: {
        connection_id: connection.id,
        user_id: userId,
        status: 'COMPLETED',
        started_at: new Date(Date.now() - 3600000),
        completed_at: new Date()
      }
    });

    const resource1 = await prisma.resources.create({
      data: {
        scan_job_id: scanJob.id,
        resource_type: 's3_bucket',
        provider_resource_id: 'arn:aws:s3:::my-public-reports',
        name: 'my-public-reports',
        region: 'us-east-1',
        configuration: { "is_public": true, "bucket_name": "my-public-reports", "versioning_enabled": false }
      }
    });

    const resource2 = await prisma.resources.create({
      data: {
        scan_job_id: scanJob.id,
        resource_type: 'security_group',
        provider_resource_id: 'sg-0a8b9c10d11e12f',
        name: 'default',
        region: 'us-west-2',
        configuration: { "group_id": "sg-0a8b9c10d11e12f", "group_name": "default", "ip_permissions": [{ "to_port": 22, "from_port": 22, "ip_ranges": [{ "cidr_ip": "0.0.0.0/0" }], "ip_protocol": "tcp" }] }
      }
    });

    await prisma.findings.create({
      data: {
        scan_job_id: scanJob.id,
        resource_id: resource1.id,
        rule_id: 'AWS-S3-001',
        status: 'FAIL',
        details: { "reason": "Bucket permissions set to public read via ACL." }
      }
    });

    await prisma.findings.create({
      data: {
        scan_job_id: scanJob.id,
        resource_id: resource2.id,
        rule_id: 'AWS-EC2-001',
        status: 'FAIL',
        details: { "reason": "Port 22 is open to the entire internet (0.0.0.0/0)." }
      }
    });
    console.log('Dummy data seeded successfully!');
  } else {
    console.log('Dummy data already exists for this user. Skipping seed.');
  }

  console.log('--- Database Seed Complete ---');
}

seed()
  .catch(e => {
    console.error('Seed Error:', e);
  })
  .finally(async () => {
    await prisma.$disconnect();
    pool.end();
  });
